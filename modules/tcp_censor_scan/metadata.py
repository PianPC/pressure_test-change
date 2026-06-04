from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_metadata(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "metadata.json"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_metadata(run_dir: Path, metadata: dict[str, Any]) -> None:
    path = run_dir / "metadata.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(metadata, fh, ensure_ascii=False, indent=2)


def update_stage(run_dir: Path, stage: str, status: str, **extra: Any) -> None:
    metadata = read_metadata(run_dir)
    stages = metadata.setdefault("stages", {})
    current = stages.setdefault(stage, {})
    current.update({"status": status, **extra})
    if status == "running":
        metadata["current_stage"] = stage
        current.setdefault("started_at", now_iso())
    if status in {"completed", "failed", "skipped", "stopped"}:
        current["ended_at"] = now_iso()
        if metadata.get("current_stage") == stage and status in {"failed", "stopped"}:
            metadata["current_stage"] = None
    write_metadata(run_dir, metadata)
