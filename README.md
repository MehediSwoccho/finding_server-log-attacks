# Local AI Security Log Analyzer

A small, local-only FastAPI app for triaging `.log` / `.txt` files with a CPU GGUF model. Logs and SQLite checkpoints stay under `.security_analyzer/`; inference does not call a cloud API. The web UI is served by FastAPI.

## Hardware and model

Designed for **4 GB RAM, 2 vCPU, no GPU**. The default recommendation is a **Qwen3.5 0.8B Q4 GGUF**; the supported alternative is a Qwen3.5 2B Q4 GGUF if its runtime memory fits your system. Point `LOCAL_MODEL_PATH` at the local model file. This project does not download weights. The model's GGUF must include a chat template supported by the installed llama.cpp version.

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

4. Place a compatible Qwen3.5 Q4 GGUF locally, then set the model path (absolute path recommended):

   ```powershell
   $env:LOCAL_MODEL_PATH = "D:\models\Qwen3.5-0.8B-Q4_K_M.gguf"
   ```

5. Start the server:

   ```powershell
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

6. Open `http://127.0.0.1:8000`. Keep the server bound to localhost unless access from another machine is explicitly desired. To work offline after setup, stage Python wheels/dependencies and the GGUF before disconnecting; the running app itself makes no external model or API requests.

Optional environment settings:

- `LOCAL_MODEL_PATH`: GGUF path (default: `models/Qwen3.5-0.8B-Q4_K_M.gguf` in the project directory).
- `ANALYZER_DATA_DIR`: directory for uploads and the SQLite database (default `.security_analyzer/`).
- `ANALYZER_DB_PATH`: override the SQLite file path.
- `MAX_UPLOAD_MB`: upload limit in MiB (default 25).

## How processing works

1. `POST /upload` accepts only `.log` and `.txt`, streams request data to disk in 1 MiB blocks, enforces the size limit while streaming, rejects empty files, and returns a job ID. It does not keep a second whole-file copy in application memory.
2. The parser reads line-by-line. Valid JSON objects are compacted to time, client IP, method, path, status, username, auth result, message, security rule, and a non-browser user agent; noisy host, response-bytes, and browser user-agent fields are omitted. Invalid JSON lines are treated as plain text. Every rendered entry retains its original 1-based line number.
3. Entries are token-counted using `llama.tokenize` and packed whole into chunks of at most 900 log tokens. An individual entry larger than the chunk budget is rejected rather than split. Chunks and cumulative entity-ledger snapshots are checkpointed in SQLite.
4. A code-maintained per-IP ledger tracks failed/successful authentications, first/last line, distinct sensitive paths, status counts, and whether a successful login followed at least three failures. A compact, prioritized snapshot (up to 250 tokens) is included in each chunk call.
5. Each call uses a 350-token system budget, 900 log-token budget, 250 ledger-token budget, and 500 output-token reserve. The prompt and reserve are re-counted before inference and must stay below 2,048 tokens. Calls are serialized, JSON-schema constrained, limited to 120 seconds, retried twice with backoff, and passed through a JSON repair fallback. Results are saved to SQLite immediately after successful calls.
6. `POST /jobs/{job_id}/start` starts or resumes incomplete chunks. `GET /jobs/{job_id}` reports status/progress/RAM/timing; `GET /jobs/{job_id}/report` returns one merged final report. Completed chunk results survive process restarts. A running job is marked paused at startup and can be resumed by posting its job ID to the start endpoint.
7. Findings are merged by entity and attack type, evidence line numbers are unioned, severity takes the maximum, and a brute-force finding is upgraded to account compromise when the ledger confirms a later success after repeated failures. Prompt-injection instructions in log data are separately identified as untrusted attempted injections.

## API summary

- `POST /upload` — multipart field `file`; returns `job_id`.
- `POST /jobs/{job_id}/start` — start or resume analysis.
- `GET /jobs/{job_id}` — progress, last call duration, process RAM, and errors.
- `GET /jobs/{job_id}/report` — final merged findings.
- `GET /health` — local service health.

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
- The 0.8B model has limited reasoning capability; small CPU models can miss subtle attacks or produce false positives. Heuristics explicitly suppress common benign operational events and single login typos, but cannot eliminate every error.
- Checkpoints and uploaded logs are stored locally without encryption. Protect the data directory and remove it when no longer needed. There is no authentication or multi-user isolation; bind to localhost.
- GGUF chat-template and Qwen3.5 support depends on the selected llama.cpp/llama-cpp-python release and model conversion. Verify the chosen model on this machine before processing sensitive production logs.
