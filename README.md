# Local AI Security Log Analyzer

A small, local-only FastAPI app for triaging `.log` / `.txt` files with a CPU GGUF model. Logs and SQLite checkpoints stay under `.security_analyzer/`; inference does not call a cloud API. The web UI is served by FastAPI.

## Hardware and model

Designed for **4 GB RAM, 2 vCPU, no GPU**. The default model is **Qwen3.5 2B Q4_K_M GGUF**, `Qwen3.5-2B-Q4_K_M.gguf`, from [Unsloth's Hugging Face repository](https://huggingface.co/unsloth/Qwen3.5-2B-GGUF). The downloaded file is 1,280,835,840 bytes (1.28 GB decimal, about 1.19 GiB). Alternate repositories/files can be selected with environment settings below. A compatible 0.8B Q4 GGUF can be used for tighter memory limits. The selected GGUF and its chat template must be supported by the installed llama.cpp version.

Runtime settings are deliberately constrained: llama.cpp context 2,048, 2 CPU threads, no GPU layers, mmap enabled, and a 64-token batch. Keep other applications modest on 4 GB machines. Quantization variants and llama.cpp versions can differ in memory use and chat-template support.

## Setup (Windows PowerShell)

1. Install a supported Python (3.11 or newer) and C++ build tools if a compatible CPU wheel for `llama-cpp-python` is unavailable.
2. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies. Prefer the upstream CPU wheel index on Windows to avoid a native compiler build. If no compatible wheel is available, install Visual Studio C++ Build Tools and CMake and build for CPU (CUDA is not used):

   ```powershell
   pip install fastapi 'uvicorn[standard]' python-multipart psutil json-repair huggingface-hub
   pip install --only-binary=:all: --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu 'llama-cpp-python>=0.3.36'
   ```

   For a source build, run `$env:CMAKE_ARGS = "-DGGML_CUDA=OFF"` before `pip install -r requirements.txt`.

4. Download the default model once (requires an internet connection for this setup step only):

   ```powershell
   python scripts/download_model.py
   ```

   This downloads `Qwen3.5-2B-Q4_K_M.gguf` into `models/`; it skips the download if the target file already exists. The app does not download models on startup. To select a different repository/file/path, set the environment variables below before running the script and server.

5. Start the server. Startup loads the selected model once; the server reports a clear startup error if it is missing or incompatible:

   ```powershell
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

6. Open `http://127.0.0.1:8000`. Keep the server bound to localhost unless access from another machine is explicitly desired. The downloader contacts Hugging Face only when explicitly run; inference and app runtime are local and do not call cloud inference APIs. To work offline after setup, stage Python wheels/dependencies and the GGUF before disconnecting.

## Setup (Linux)

1. Install Python 3.11+ and the native CPU build tools (`build-essential` and `cmake` on Debian/Ubuntu). Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies with the CPU backend selected, download the model once, and start the local server:

   ```bash
   export CMAKE_ARGS="-DGGML_CUDA=OFF"
   pip install -r requirements.txt
   python scripts/download_model.py
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

3. Open `http://127.0.0.1:8000`. Model download is setup-time network activity; inference makes no cloud API calls. Keep the GGUF and installed wheels available for subsequent offline runs.

Optional environment settings:

- `MODEL_REPO_ID`: Hugging Face repository for setup-time downloads (default `unsloth/Qwen3.5-2B-GGUF`).
- `MODEL_FILENAME`: GGUF filename in that repository (default `Qwen3.5-2B-Q4_K_M.gguf`).
- `MODEL_REVISION`: repository branch, tag, or commit (default `main`; pin a commit for reproducible downloads).
- `MODEL_DIR`: model download directory (default `models/`).
- `LOCAL_MODEL_PATH`: exact local GGUF path used by the app; when set, its basename is the default download filename unless `MODEL_FILENAME` is also set.
- `ANALYZER_DATA_DIR`: directory for uploads and the SQLite database (default `.security_analyzer/`).
- `ANALYZER_DB_PATH`: override the SQLite file path.
- `MAX_UPLOAD_MB`: upload limit in MiB (default 25).

For example, select another public GGUF repository before downloading and launching:

```powershell
$env:MODEL_REPO_ID = "owner/model-GGUF"
$env:MODEL_FILENAME = "model-Q4_K_M.gguf"
$env:MODEL_REVISION = "main"
$env:LOCAL_MODEL_PATH = "$PWD/models/model-Q4_K_M.gguf"
python scripts/download_model.py
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## How processing works

1. `POST /upload` accepts only `.log` and `.txt`, streams request data to disk in 1 MiB blocks, enforces the size limit while streaming, rejects empty/binary files with JSON errors, and returns a job ID. It does not keep a second whole-file copy in application memory.
2. The parser streams the upload file line-by-line. Valid JSON objects are compacted to time, client IP, method, path, status, username, auth result, message, security rule, and a non-browser user agent; noisy host, response-bytes, and browser user-agent fields are omitted. Invalid JSON and non-object JSONL lines fall back to their original raw text. Every rendered record retains its original 1-based source line. `event_id`, when present, is retained as internal provenance, not added to model log text.
3. The chunker counts the serialized entries with the loaded llama tokenizer. It greedily packs newline-joined complete entries into chunks of at most 900 tokens; it never splits an entry. An individual entry exceeding the chunk budget fails preparation with its source line rather than truncating it. Chunk input, ledger snapshot, token count, results, errors, and timings are stored in SQLite.
4. A persisted code-maintained ledger tracks facts separately per client IP and username: failed/successful authentications, first/last source line, distinct paths, status counts, sensitive-path hits, and (for IPs) the successful-login line after at least three earlier failures. Each chunk receives a top-priority snapshot captured before that chunk starts, bounded to 250 model-tokenizer tokens. It is context only, with no attack labels or conclusions.
5. The allocation is 350 system + 900 log + 250 ledger + 500 output-reserve tokens = 2,000, strictly below the 2,048 context. Before each call, the app asserts both that allocation and the actual rendered chat-template prompt plus output reserve fit. Calls are serialized, JSON-Schema constrained, limited to 120 seconds, retried twice with 1.5s/3s backoff, and parsed with a JSON repair fallback. Successful chunk findings are committed immediately. A chunk that exhausts retries records its error and the runner continues with the remaining chunks.
6. `POST /jobs/{job_id}/start` starts or resumes incomplete/failed chunks, skipping completed chunks. `GET /jobs/{job_id}` reports progress/RAM/timing; `GET /api/jobs/{job_id}/progress` streams JSON events via SSE; `GET /jobs/{job_id}/report` returns the merged report, including completed chunks if another chunk failed. The report panel exports JSON. On restart, SQLite marks previously running jobs paused; successful chunks survive and the client can resume the same job.
7. Findings are merged by `(entity, attack_type)`, event-ID duplicate line references are canonicalized to the earliest original line, evidence is unioned, and severity takes the maximum. A model-produced brute-force finding is upgraded to `account_compromise` when the IP ledger records at least three failures followed by a success. This is a deterministic sequence rule, not a hardcoded sample result. Routine operational errors are filtered from findings; analyzer-directed log instructions are identified as attempted prompt injection.

## API summary

- `POST /upload` — multipart field `file`; returns `job_id`.
- `POST /jobs/{job_id}/start` — start or resume analysis.
- `GET /jobs/{job_id}` — progress, last call duration, process RAM, and errors.
- `GET /jobs/{job_id}/report` — final merged findings.
- `GET /jobs/{job_id}/lines/{line_number}` — original uploaded source line for a clickable evidence reference.
- `GET /health` — local service health.
- `GET /api/health` — loaded model name, process RSS in MB, and most recent model-call latency in milliseconds (`null` before the first call).

Upload errors use JSON `detail.error` messages. The UI presents these messages, per-call timing, process memory, progress, severity badges, and evidence lines.

## Tests

Run the standard-library tests from the project directory:

```powershell
python -m unittest discover -s tests -v
```

Tests cover whole-entry chunk packing, original line references, oversized entries, and malformed JSON repair. They do not load a model.

## Known limits

- Detection is a triage aid, not a SIEM, incident-response system, or guarantee of attack detection. Validate high-impact findings against source systems.
- Input is line-oriented JSONL or plain text; deeply nested JSON fields are intentionally not expanded, and only the documented common aliases are normalized.
- A single rendered event exceeding 900 tokens cannot be split safely and causes preparation to fail with its source line number.
- Small CPU models can miss subtle attacks or produce false positives. The 2B Q4 model uses more memory than the 0.8B alternative; actual RAM use varies with the llama.cpp build and workload. Heuristics explicitly suppress common benign operational events and single login typos, but cannot eliminate every error.
- Checkpoints and uploaded logs are stored locally without encryption. Protect the data directory and remove it when no longer needed. There is no authentication or multi-user isolation; bind to localhost.
- GGUF chat-template and Qwen3.5 support depends on the selected llama.cpp/llama-cpp-python release and model conversion. Verify the chosen model on this machine before processing sensitive production logs.

## Measured results (sample log, 258 lines)

| Metric | Value |
| --- | --- |
| Model | Qwen3.5 0.8B Q4_K_M |
| Model calls (chunks) | 22 |
| Total analysis time | 470 s (about 21 s per call) |
| Peak server RAM (RSS) | 909.9 MB |
| Test machine | AMD Ryzen 7 5700U with Radeon Graphics, 7.3 GB RAM |

Measured with `measure.py` against a running local server. Peak RAM is the server process memory sampled every 2 seconds.
