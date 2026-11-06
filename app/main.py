from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import analyzer, db
from .config import MAX_UPLOAD_BYTES, UPLOAD_DIR

app = FastAPI(title="Local AI Security Log Analyzer", version="1.0.0")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
_active_tasks: dict[str, asyncio.Task[None]] = {}


@app.on_event("startup")
def startup() -> None:
    db.initialize_database()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.post("/upload", status_code=201)
async def upload_log(file: UploadFile = File(...)) -> dict[str, Any]:
    filename = Path(file.filename or "").name
    if Path(filename).suffix.lower() not in {".log", ".txt"}:
        await file.close()
        raise HTTPException(status_code=400, detail={"error": "Only .log and .txt files are accepted."})

    job_id = uuid.uuid4().hex
    destination = UPLOAD_DIR / f"{job_id}{Path(filename).suffix.lower()}"
    size = 0
    try:
        with destination.open("xb") as output:
            while block := await file.read(1024 * 1024):
                size += len(block)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail={"error": f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."},
                    )
                output.write(block)
        if size == 0:
            raise HTTPException(status_code=400, detail={"error": "The uploaded file is empty."})
        db.create_job(job_id, filename, str(destination))
        return {"job_id": job_id, "filename": filename, "size_bytes": size, "status": "uploaded"}
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail={"error": f"Could not store upload: {exc}"}) from exc
    finally:
        await file.close()


@app.post("/jobs/{job_id}/start", status_code=202)
async def start_job(job_id: str) -> dict[str, Any]:
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": "Job not found."})
    task = _active_tasks.get(job_id)
    if task and not task.done():
        return {"job_id": job_id, "status": "running", "message": "Analysis is already in progress."}
    if job["status"] == "completed":
        return {"job_id": job_id, "status": "completed", "message": "This job already has a final report."}
    task = asyncio.create_task(analyzer.start_analysis(job_id), name=f"analysis-{job_id}")
    _active_tasks[job_id] = task
    task.add_done_callback(lambda completed, key=job_id: _active_tasks.pop(key, None))
    return {"job_id": job_id, "status": "running", "message": "Analysis started; progress is checkpointed in SQLite."}


@app.get("/jobs/{job_id}")
async def get_progress(job_id: str) -> dict[str, Any]:
    result = db.progress(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "Job not found."})
    try:
        import psutil

        process = psutil.Process(os.getpid())
        result["ram_used_mb"] = round(process.memory_info().rss / (1024 * 1024), 1)
        result["ram_total_mb"] = round(psutil.virtual_memory().total / (1024 * 1024), 1)
    except ImportError:
        result["ram_used_mb"] = None
        result["ram_total_mb"] = None
    return result


@app.get("/jobs/{job_id}/report")
def get_report(job_id: str) -> dict[str, Any]:
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": "Job not found."})
    if not job["report_json"]:
        raise HTTPException(status_code=409, detail={"error": "The final report is not ready yet."})
    return db.decode_json(job["report_json"], {"findings": []})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-only"}
