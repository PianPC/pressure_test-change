from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import sqlite3

from .config import repo_root


def list_ip_resources(ip_root: str | Path | None = None) -> list[dict[str, Any]]:
    try:
        from ...shared.ip_resource_manager import IPResourceManager
        manager = IPResourceManager()
        result = manager.list_resources(filter_type=None, filter_source=None, filter_country=None, filter_protocol=None)
        return [
            {
                "name": r["filename"].replace(".txt", ""),
                "filename": r["filename"],
                "path": r["path"],
                "bytes": r.get("size_bytes", 0),
                "non_empty_lines": r.get("non_empty_lines", 0),
            }
            for r in result["resources"]
        ]
    except ImportError:
        roots: list[Path] = []
        if ip_root:
            roots.append(Path(ip_root))
        else:
            roots.append(repo_root() / "attack_resources" / "tcp" / "resources" / "ip_lists")
            shared = repo_root() / "attack_resources" / "shared" / "ip_lists"
            if shared.exists():
                roots.append(shared)

        seen: set[str] = set()
        resources: list[dict[str, Any]] = []
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(root.glob("*.txt")):
                if path.name in seen:
                    continue
                seen.add(path.name)
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


def _count_non_empty_lines(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count
