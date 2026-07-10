from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import sqlite3

from attack_resources.shared.ip_resource_catalog import list_protocol_resources

from .config import repo_root


ATTACK_RESOURCES_ROOT = repo_root() / "attack_resources"


def list_ip_resources(ip_root: str | Path | None = None) -> list[dict[str, Any]]:
    resources = list_protocol_resources("tcp", ATTACK_RESOURCES_ROOT)
    return [_to_tcp_resource(item) for item in resources]


def list_runs(output_root: str | Path | None = None) -> list[dict[str, Any]]:
    root = Path(output_root) if output_root else repo_root() / "attack_resources" / "tcp" / "runs" / "tcp_censor_scan"
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
            "current_stage": metadata.get("current_stage"),
            "error": metadata.get("error", ""),
            "stop_requested": metadata.get("stop_requested", False),
            "pkt_method": metadata.get("config", {}).get("pkt_method"),
            "target_host": metadata.get("config", {}).get("target_host"),
            "dry_run": metadata.get("config", {}).get("dry_run"),
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
        "current_stage": metadata.get("current_stage"),
        "error": metadata.get("error", ""),
        "started_at": metadata.get("started_at"),
        "ended_at": metadata.get("ended_at"),
        "stop_requested": metadata.get("stop_requested", False),
        "cleanup_requested": metadata.get("cleanup_requested", False),
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
    root = Path(output_root) if output_root else repo_root() / "attack_resources" / "tcp" / "runs" / "tcp_censor_scan"
    run_dir = root / run_id
    if not run_dir.exists():
        raise FileNotFoundError(f"Run not found: {run_id}")
    return run_dir


def read_run_file(run_id: str, filename: str, output_root: str | Path | None = None) -> dict[str, Any]:
    run_dir = _run_dir(run_id, output_root)
    file_path = _resolve_run_file(run_dir, filename)
    suffix = file_path.suffix.lower()
    if suffix == ".db":
        return {
            "name": file_path.name,
            "path": str(file_path),
            "type": "db",
            "editable": False,
            "preview": _read_db_preview(file_path),
        }
    content = file_path.read_text(encoding="utf-8", errors="replace")
    return {
        "name": file_path.name,
        "path": str(file_path),
        "type": "text",
        "editable": suffix in {".log", ".txt", ".csv", ".json"},
        "content": content,
    }


def write_run_file(run_id: str, filename: str, content: str, output_root: str | Path | None = None) -> dict[str, Any]:
    run_dir = _run_dir(run_id, output_root)
    file_path = _resolve_run_file(run_dir, filename)
    if file_path.suffix.lower() not in {".log", ".txt", ".csv", ".json"}:
        raise ValueError("File type is not editable")
    file_path.write_text(content, encoding="utf-8")
    return {
        "name": file_path.name,
        "path": str(file_path),
        "bytes": file_path.stat().st_size,
    }


def _resolve_run_file(run_dir: Path, filename: str) -> Path:
    candidate = (run_dir / filename).resolve()
    run_root = run_dir.resolve()
    if run_root not in candidate.parents and candidate != run_root:
        raise FileNotFoundError("File not found")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError("File not found")
    return candidate


def _read_db_preview(path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(path)
    try:
        cursor = conn.cursor()
        tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        preview_tables = []
        for table in tables[:3]:
            columns = [row[1] for row in cursor.execute(f"PRAGMA table_info({table})")]
            rows = cursor.execute(f"SELECT * FROM {table} LIMIT 20").fetchall()
            preview_tables.append({
                "name": table,
                "columns": columns,
                "rows": rows,
            })
        return {
            "tables": tables,
            "preview_tables": preview_tables,
        }
    finally:
        conn.close()


def _to_tcp_resource(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item["id"],
        "name": item["display_name"],
        "filename": item["filename"],
        "path": item["path"],
        "full_path": item["full_path"],
        "bytes": item.get("bytes", item.get("size_bytes", 0)),
        "non_empty_lines": item.get("non_empty_lines", 0),
        "entry_count": item.get("entry_count", 0),
        "count": item.get("count", 0),
        "sub_dir": item.get("sub_dir", ""),
        "source": item.get("source"),
        "source_name": item.get("source_name"),
        "type": item.get("type"),
        "protocols": item.get("protocols", []),
        "updated_at": item.get("updated_at"),
        "legacy": item.get("legacy", False),
        "location_label": item.get("location_label"),
    }
