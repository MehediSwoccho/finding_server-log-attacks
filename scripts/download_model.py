from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import MODEL_FILENAME, MODEL_PATH, MODEL_REPO_ID, MODEL_REVISION


def download_model(
    repo_id: str = MODEL_REPO_ID,
    filename: str = MODEL_FILENAME,
    revision: str = MODEL_REVISION,
    destination: Path = MODEL_PATH,
    force: bool = False,
) -> Path:
    """Download one GGUF from Hugging Face into the configured local model path."""
    if Path(filename).name != filename or not filename.lower().endswith(".gguf"):
        raise ValueError("filename must be a root-level .gguf filename")
    destination = destination.expanduser().resolve()
    if destination.is_file() and not force:
        print(f"Model already exists; skipping download: {destination}")
        return destination

    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise RuntimeError("Install project dependencies first (huggingface-hub is required).") from exc

    destination.parent.mkdir(parents=True, exist_ok=True)
    downloaded = Path(
        hf_hub_download(
            repo_id=repo_id,
            filename=filename,
            revision=revision,
            local_dir=str(destination.parent),
            force_download=force,
        )
    ).resolve()
    if downloaded != destination:
        os.replace(downloaded, destination)
    print(f"Model ready: {destination}")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Download one local Qwen GGUF model from Hugging Face.")
    parser.add_argument("--repo-id", default=MODEL_REPO_ID, help="Hugging Face model repository ID")
    parser.add_argument("--filename", default=MODEL_FILENAME, help="GGUF filename in the repository")
    parser.add_argument("--revision", default=MODEL_REVISION, help="Repository branch, tag, or commit")
    parser.add_argument(
        "--model-path",
        type=Path,
        default=MODEL_PATH,
        help="Destination path (defaults to LOCAL_MODEL_PATH or MODEL_DIR/MODEL_FILENAME)",
    )
    parser.add_argument("--force", action="store_true", help="Redownload even if the destination file exists")
    args = parser.parse_args()

    try:
        download_model(args.repo_id, args.filename, args.revision, args.model_path, args.force)
    except Exception as exc:
        print(f"Model download failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
