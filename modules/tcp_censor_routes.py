from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from threading import Lock, Thread
from typing import Any
import traceback

from flask import Blueprint, jsonify, request

from modules.tcp_censor_scan import (
    load_config,
    list_ip_resources,
    list_runs,
    read_result_summary,
    read_run_log,
    run_pipeline,
    stop_run,
)
from modules.tcp_censor_scan.config import ConfigError, ScanConfig, repo_root, validate_config


tcp_censor_bp = Blueprint("tcp_censor_scan", __name__, url_prefix="/api/tcp-scan")

DEFAULT_CONFIG_PATH = repo_root() / "config" / "tcp_censor_scan" / "scan.example.toml"
TCP_OUTPUT_ROOT = repo_root() / "runs" / "tcp_censor_scan"


class TcpScanState:
    def __init__(self) -> None:
        self.lock = Lock()
        self.thread: Thread | None = None
        self.current_run_id: str | None = None
        self.error: str = ""

    def is_running(self) -> bool:
        return bool(self.thread and self.thread.is_alive())


tcp_scan_state = TcpScanState()


@tcp_censor_bp.route("/resources", methods=["GET"])
def tcp_scan_resources():
    return jsonify({"success": True, "resources": list_ip_resources(repo_root() / "tcp_scan_data" / "ip_lists")})


@tcp_censor_bp.route("/runs", methods=["GET"])
def tcp_scan_runs():
    return jsonify({
        "success": True,
        "runs": list_runs(TCP_OUTPUT_ROOT),
        "active_run_id": tcp_scan_state.current_run_id if tcp_scan_state.is_running() else None,
    })


@tcp_censor_bp.route("/runs", methods=["POST"])
def tcp_scan_start():
    with tcp_scan_state.lock:
        if tcp_scan_state.is_running():
            return jsonify({"success": False, "message": "TCP scan is already running", "run_id": tcp_scan_state.current_run_id}), 409

        try:
            config = _config_from_request(request.get_json(silent=True) or {})
        except (ConfigError, ValueError) as exc:
            return jsonify({"success": False, "message": str(exc)}), 400

        tcp_scan_state.error = ""
        tcp_scan_state.current_run_id = None

        def worker() -> None:
            try:
                metadata = run_pipeline(config)
                with tcp_scan_state.lock:
                    tcp_scan_state.current_run_id = metadata.get("run_id")
            except Exception as exc:  # surfaced through logs and API status
                with tcp_scan_state.lock:
                    tcp_scan_state.error = f"{exc}\n{traceback.format_exc()}"

        tcp_scan_state.thread = Thread(target=worker, daemon=True)
        tcp_scan_state.thread.start()

    return jsonify({"success": True, "message": "TCP scan started"})


@tcp_censor_bp.route("/runs/<run_id>", methods=["GET"])
def tcp_scan_run_detail(run_id: str):
    try:
        summary = read_result_summary(run_id, TCP_OUTPUT_ROOT)
        return jsonify({"success": True, "summary": summary})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404


@tcp_censor_bp.route("/runs/<run_id>/logs", methods=["GET"])
def tcp_scan_logs(run_id: str):
    log_name = request.args.get("log", "pipeline.log")
    tail = request.args.get("tail", "200")
    try:
        tail_lines = int(tail)
    except ValueError:
        tail_lines = 200
    try:
        return jsonify({"success": True, "log": read_run_log(run_id, log_name, TCP_OUTPUT_ROOT, tail_lines)})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404


@tcp_censor_bp.route("/runs/<run_id>/stop", methods=["POST"])
def tcp_scan_stop(run_id: str):
    stopped = stop_run(run_id, TCP_OUTPUT_ROOT)
    return jsonify({"success": stopped, "message": "Stopping TCP scan" if stopped else "No running process found"})


@tcp_censor_bp.route("/state", methods=["GET"])
def tcp_scan_state_view():
    return jsonify({
        "success": True,
        "running": tcp_scan_state.is_running(),
        "active_run_id": tcp_scan_state.current_run_id,
        "error": tcp_scan_state.error,
    })


def _config_from_request(data: dict[str, Any]) -> ScanConfig:
    base = load_config(DEFAULT_CONFIG_PATH)
    ip_file = _resolve_ip_file(str(data.get("ip_file") or base.ip_file))
    cfg = replace(
        base,
        ip_file=ip_file,
        target_host=str(data.get("target_host") or base.target_host).strip(),
        pkt_method=str(data.get("pkt_method") or base.pkt_method).strip(),
        scan_rate=_int(data.get("scan_rate", base.scan_rate), "scan_rate", 1),
        result_limit=_int(data.get("result_limit", base.result_limit), "result_limit", 0),
        length_threshold=_int(data.get("length_threshold", base.length_threshold), "length_threshold", 0),
        geoip_db_path=Path(data.get("geoip_db_path") or base.geoip_db_path),
        scan_count=_int(data.get("scan_count", base.scan_count), "scan_count", 1, 100),
        ttl=_int(data.get("ttl", base.ttl), "ttl", 1, 255),
        network_interface=str(data.get("network_interface") or base.network_interface).strip(),
        output_root=TCP_OUTPUT_ROOT,
        dry_run=_bool(data.get("dry_run", base.dry_run)),
    )
    return validate_config(cfg)


def _resolve_ip_file(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() and path.exists():
        return path
    ip_root = repo_root() / "tcp_scan_data" / "ip_lists"
    candidate = ip_root / path.name
    if candidate.exists():
        return candidate
    return repo_root() / value


def _int(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if number < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and number > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return number


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)
