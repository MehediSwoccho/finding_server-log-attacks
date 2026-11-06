# Local AI Security Log Analyzer

A small, local-only FastAPI app for triaging `.log` / `.txt` files with a CPU GGUF model. Logs and SQLite checkpoints stay under `.security_analyzer/`; inference does not call a cloud API. The web UI is served by FastAPI.

## Hardware and model

Designed for **4 GB RAM, 2 vCPU, no GPU**. The default model is the **Qwen3.5 2B Q4_K_M GGUF** from [Unsloth's Hugging Face repository](https://huggingface.co/unsloth/Qwen3.5-2B-GGUF) (about 1.28 GB). An alternate repository/file can be selected with environment settings below. The 0.8B Q4 model is an option for tighter memory budgets. The model's GGUF must be supported by the installed llama.cpp version.

Runtime settings are deliberately constrained: llama.cpp context 2,048, 2 CPU threads, no GPU layers, mmap enabled, and a 64-token batch. Keep other applications modest on 4 GB machines. Quantization variants and llama.cpp versions can differ in memory use and chat-template support.

## Setup (Windows PowerShell)

1. Install a supported Python (3.11 or newer) and C++ build tools if a compatible CPU wheel for `llama-cpp-python` is unavailable.
2. Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies. On Windows, `llama-cpp-python` may need a local CPU build toolchain; CUDA is not used:

   ```powershell
   $env:CMAKE_ARGS = "-DGGML_CUDA=OFF"
   pip install -r requirements.txt
   ```

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
2. The parser reads line-by-line. Valid JSON objects are compacted to time, client IP, method, path, status, username, auth result, message, security rule, and a non-browser user agent; noisy host, response-bytes, and browser user-agent fields are omitted. Invalid JSON lines are treated as plain text. Every rendered entry retains its original 1-based line number.
3. Entries are token-counted using `llama.tokenize` and packed whole into chunks of at most 900 log tokens. An individual entry larger than the chunk budget is rejected rather than split. Chunks and cumulative entity-ledger snapshots are checkpointed in SQLite.
4. A persisted code-maintained ledger tracks those facts separately per client IP and username: failed/successful authentications, first/last line, distinct paths, status counts, and sensitive-path hit counts. Each chunk stores a compact, prioritized snapshot of facts from earlier chunks (at most 250 tokens); it contains no attack labels or conclusions, leaving attack classification to the model.
5. Each call uses a 350-token system budget, 900 log-token budget, 250 ledger-token budget, and 500 output-token reserve. The prompt and reserve are re-counted before inference and must stay below 2,048 tokens. Calls are serialized, JSON-schema constrained, limited to 120 seconds, retried twice with backoff, and passed through a JSON repair fallback. Results are saved to SQLite immediately after successful calls; failed chunks record their error and the runner continues with later chunks.
6. `POST /jobs/{job_id}/start` starts or resumes incomplete/failed chunks. `GET /jobs/{job_id}` reports status/progress/RAM/timing; `GET /api/jobs/{job_id}/progress` streams JSON events (`chunk`, elapsed seconds, RAM, call duration) via SSE; `GET /jobs/{job_id}/report` returns one merged final report, including successful chunks when some chunks failed. Completed chunk results survive process restarts. A running job is marked paused at startup and can be resumed by posting its job ID to the start endpoint.
7. Findings are merged by entity and attack type, evidence line numbers are unioned, and severity takes the maximum. Attack classification comes from the model; the ledger provides only factual context. Prompt-injection instructions in log data are separately identified as untrusted attempted injections.

## API summary

- `POST /upload` — multipart field `file`; returns `job_id`.
- `POST /jobs/{job_id}/start` — start or resume analysis.
- `GET /jobs/{job_id}` — progress, last call duration, process RAM, and errors.
- `GET /jobs/{job_id}/report` — final merged findings.
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
