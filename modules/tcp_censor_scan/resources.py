from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from .config import repo_root


def list_ip_resources(ip_root: str | Path | None = None) -> list[dict[str, Any]]:
    root = Path(ip_root) if ip_root else repo_root() / "tcp_scan_data" / "ip_lists"
    if not root.exists():
        return []
    resources = []
    for path in sorted(root.glob("*.txt")):
        line_count = _count_non_empty_lines(path)
        resources.append({
            "name": path.stem,
            "filename": path.name,
            "path": str(path),
            "bytes": path.stat().st_size,
            "non_empty_lines": line_count,
        })
    return resources


def list_runs(output_root: str | Path | None = None) -> list[dict[str, Any]]:
    root = Path(output_root) if output_root else repo_root() / "runs" / "tcp_censor_scan"
    if not root.exists():
        return []
    runs = []
    for path in sorted((p for p in root.iterdir() if p.is_dir()), reverse=True):
        metadata_path = path / "metadata.json"
        metadata: dict[str, Any] = {}
        if metadata_path.exists():
            with metadata_path.open("r", encoding="utf-8") as fh:
                metadata = json.load(fh)
        runs.append({
            "run_id": path.name,
            "path": str(path),
            "status": metadata.get("status", "unknown"),
            "started_at": metadata.get("started_at"),
            "ended_at": metadata.get("ended_at"),
            "pkt_method": metadata.get("config", {}).get("pkt_method"),
            "target_host": metadata.get("config", {}).get("target_host"),
        })
    return runs


def read_run_log(run_id: str, log_name: str = "pipeline.log", output_root: str | Path | None = None, tail_lines: int | None = None) -> str:
    run_dir = _run_dir(run_id, output_root)
    log_path = run_dir / log_name
    if not log_path.exists():
        return ""
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if tail_lines is not None and tail_lines > 0:
        lines = lines[-tail_lines:]
    return "\n".join(lines)


def read_result_summary(run_id: str, output_root: str | Path | None = None) -> dict[str, Any]:
    run_dir = _run_dir(run_id, output_root)
    metadata_path = run_dir / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        with metadata_path.open("r", encoding="utf-8") as fh:
            metadata = json.load(fh)
    artifacts = metadata.get("artifacts", {})
    return {
        "run_id": run_id,
        "status": metadata.get("status", "unknown"),
        "config": metadata.get("config", {}),
        "stages": metadata.get("stages", {}),
        "artifacts": artifacts,
        "files": [
            {"name": path.name, "path": str(path), "bytes": path.stat().st_size}
            for path in sorted(run_dir.iterdir())
            if path.is_file()
        ],
    }


def _run_dir(run_id: str, output_root: str | Path | None = None) -> Path:
    root = Path(output_root) if output_root else repo_root() / "runs" / "tcp_censor_scan"
    run_dir = root / run_id
    if not run_dir.exists():
        raise FileNotFoundError(f"Run not found: {run_id}")
    return run_dir


def _count_non_empty_lines(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count
