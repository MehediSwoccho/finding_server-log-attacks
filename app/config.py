from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("ANALYZER_DATA_DIR", PROJECT_ROOT / ".security_analyzer")).resolve()
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = Path(os.getenv("ANALYZER_DB_PATH", DATA_DIR / "checkpoints.sqlite3")).resolve()
MODEL_DIR = Path(os.getenv("MODEL_DIR", PROJECT_ROOT / "models")).expanduser().resolve()
_LOCAL_MODEL_PATH = os.getenv("LOCAL_MODEL_PATH")
MODEL_FILENAME = os.getenv(
    "MODEL_FILENAME",
    Path(_LOCAL_MODEL_PATH).name if _LOCAL_MODEL_PATH else "Qwen3.5-2B-Q4_K_M.gguf",
)
MODEL_PATH = (
    Path(_LOCAL_MODEL_PATH).expanduser().resolve()
    if _LOCAL_MODEL_PATH
    else (MODEL_DIR / MODEL_FILENAME).resolve()
)
MODEL_REPO_ID = os.getenv("MODEL_REPO_ID", "unsloth/Qwen3.5-2B-GGUF")
MODEL_REVISION = os.getenv("MODEL_REVISION", "main")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "25")) * 1024 * 1024
MODEL_CONTEXT = 2048
MAX_LOG_TOKENS = 900
MAX_LEDGER_TOKENS = 250
SYSTEM_TOKEN_BUDGET = 350
OUTPUT_TOKEN_RESERVE = 500

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
