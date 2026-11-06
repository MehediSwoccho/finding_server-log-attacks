from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import psutil

from . import analyzer, db
from .config import MAX_UPLOAD_BYTES, MODEL_PATH, UPLOAD_DIR
from .upload_validation import looks_binary

app = FastAPI(title="Local AI Security Log Analyzer", version="1.0.0")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
_active_tasks: dict[str, asyncio.Task[None]] = {}
_SSE_TERMINAL_STATES = {"completed", "completed_with_errors", "failed", "paused"}


def _add_runtime_metrics(result: dict[str, Any]) -> dict[str, Any]:
    try:
        process = psutil.Process(os.getpid())
        result["ram_used_mb"] = round(process.memory_info().rss / (1024 * 1024), 1)
        result["ram_total_mb"] = round(psutil.virtual_memory().total / (1024 * 1024), 1)
    except (ImportError, OSError):
        result["ram_used_mb"] = None
        result["ram_total_mb"] = None
    return result


@app.on_event("startup")
async def startup() -> None:
    db.initialize_database()
    await analyzer.load_model_once()


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
    sniff = bytearray()
    try:
        with destination.open("xb") as output:
            while block := await file.read(1024 * 1024):
                size += len(block)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail={"error": f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."},
                    )
                if b"\x00" in block:
                    raise HTTPException(status_code=400, detail={"error": "The uploaded file appears to be binary; upload a text log."})
                if len(sniff) < 8192:
                    sniff.extend(block[: 8192 - len(sniff)])
                output.write(block)
        if size == 0:
            raise HTTPException(status_code=400, detail={"error": "The uploaded file is empty."})
        if looks_binary(bytes(sniff)):
            raise HTTPException(status_code=400, detail={"error": "The uploaded file appears to be binary; upload a text log."})
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
    return _add_runtime_metrics(result)


@app.get("/api/jobs/{job_id}/progress")
async def stream_job_progress(job_id: str) -> StreamingResponse:
    if db.get_job(job_id) is None:
        raise HTTPException(status_code=404, detail={"error": "Job not found."})

    async def events() -> AsyncIterator[str]:
        while True:
            progress = db.progress(job_id)
            if progress is None:
                return
            progress = _add_runtime_metrics(progress)
            yield "event: progress\ndata: " + json.dumps(progress, ensure_ascii=False) + "\n\n"
            if progress["status"] in _SSE_TERMINAL_STATES:
                return
            await asyncio.sleep(1)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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


@app.get("/api/health")
def api_health() -> dict[str, Any]:
    process = psutil.Process(os.getpid())
    return {
        "model_name": MODEL_PATH.stem,
        "model_loaded": True,
        "rss_memory_mb": round(process.memory_info().rss / (1024 * 1024), 1),
        "last_call_latency_ms": analyzer.last_call_latency_ms(),
    }
