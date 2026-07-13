from __future__ import annotations

import logging
import os
from dataclasses import replace
from pathlib import Path
from threading import Lock, Thread
from typing import Any
import traceback

from flask import Blueprint, jsonify, request

from attack_resources.shared.ip_resource_catalog import resolve_protocol_resource_path
from attack_resources.shared.qualified_pool import aggregate_quality_ips
from attack_resources.tcp.code.tcp_censor_scan import (
    cleanup_run_artifacts,
    load_config,
    list_ip_resources,
    list_runs,
    preflight_check,
    prepare_run,
    read_result_summary,
    read_run_file,
    read_run_log,
    run_pipeline,
    stop_run,
    write_run_file,
)
from attack_resources.tcp.code.tcp_censor_scan.config import ConfigError, ScanConfig, repo_root, validate_config


tcp_censor_bp = Blueprint("tcp_censor_scan", __name__, url_prefix="/api/tcp-scan")

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = repo_root() / "attack_resources" / "tcp" / "config" / "scan.example.toml"
TCP_OUTPUT_ROOT = repo_root() / "attack_resources" / "tcp" / "runs" / "tcp_censor_scan"


class TcpScanRegistry:
    def __init__(self) -> None:
        self.lock = Lock()
        self.threads: dict[str, Thread] = {}
        self.errors: dict[str, str] = {}

    def register(self, run_id: str, thread: Thread) -> None:
        with self.lock:
            self.threads[run_id] = thread
            self.errors.pop(run_id, None)

    def set_error(self, run_id: str, error: str) -> None:
        with self.lock:
            self.errors[run_id] = error

    def get_error(self, run_id: str) -> str:
        with self.lock:
            return self.errors.get(run_id, "")

    def is_running(self, run_id: str) -> bool:
        with self.lock:
            thread = self.threads.get(run_id)
            return bool(thread and thread.is_alive())

    def active_run_ids(self) -> list[str]:
        with self.lock:
            return [run_id for run_id, thread in self.threads.items() if thread.is_alive()]

    def forget(self, run_ids: list[str]) -> None:
        with self.lock:
            for run_id in run_ids:
                self.threads.pop(run_id, None)
                self.errors.pop(run_id, None)


tcp_scan_registry = TcpScanRegistry()


@tcp_censor_bp.route("/resources", methods=["GET"])
def tcp_scan_resources():
    return jsonify({"success": True, "resources": list_ip_resources()})


@tcp_censor_bp.route("/preflight", methods=["GET"])
def tcp_scan_preflight():
    pkt_method = request.args.get("pkt_method", "")
    dry_run = _bool(request.args.get("dry_run", "true"))
    network_interface = request.args.get("network_interface", "")
    try:
        config = _config_from_request({
            "pkt_method": pkt_method,
            "dry_run": dry_run,
            "network_interface": network_interface,
        })
        report = preflight_check(config)
        return jsonify({"success": report["ok"], "report": report, "message": "" if report["ok"] else "预检未通过"})
    except (ConfigError, ValueError) as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@tcp_censor_bp.route("/runs", methods=["GET"])
def tcp_scan_runs():
    runs = list_runs(TCP_OUTPUT_ROOT)
    active_run_ids = tcp_scan_registry.active_run_ids()
    return jsonify({
        "success": True,
        "runs": runs,
        "active_run_ids": active_run_ids,
        "running_count": len(active_run_ids),
    })


@tcp_censor_bp.route("/runs", methods=["DELETE"])
def tcp_scan_clear_runs():
    active_run_ids = set(tcp_scan_registry.active_run_ids())
    deleted: list[str] = []
    skipped: list[str] = []

    for run in list_runs(TCP_OUTPUT_ROOT):
        run_id = run.get("run_id")
        if not run_id:
            continue
        if run_id in active_run_ids:
            skipped.append(run_id)
            continue
        if cleanup_run_artifacts(run_id, TCP_OUTPUT_ROOT):
            deleted.append(run_id)

    tcp_scan_registry.forget(deleted)
    return jsonify({
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    })


@tcp_censor_bp.route("/runs", methods=["POST"])
def tcp_scan_start():
    payload = request.get_json(silent=True) or {}
    methods = payload.get("pkt_methods") or [payload.get("pkt_method")]
    created: list[dict[str, Any]] = []

    try:
        configs = [_config_from_request({**payload, "pkt_method": method}) for method in methods if method]
    except (ConfigError, ValueError) as exc:
        return jsonify({"success": False, "message": str(exc)}), 400

    for config in configs:
        if not config.dry_run:
            report = preflight_check(config)
            if not report["ok"]:
                return jsonify({"success": False, "message": "预检未通过", "report": report}), 400

    for config in configs:
        metadata = _prepare_run_metadata(config)
        run_id = metadata["run_id"]
        created.append({
            "run_id": run_id,
            "pkt_method": config.pkt_method,
            "target_host": config.target_host,
        })

        def worker(cfg: ScanConfig = config, current_run_id: str = run_id) -> None:
            try:
                run_pipeline(cfg, run_dir=TCP_OUTPUT_ROOT / current_run_id)
                try:
                    task_qualified_ips_path = os.path.join(
                        str(TCP_OUTPUT_ROOT / current_run_id), "qualified_ips.txt"
                    )
                    agg_result = aggregate_quality_ips("tcp", task_qualified_ips_path)
                    logger.info(
                        "已聚合 %d 个优质 IP 到 tcp 质量池，总计 %d 个",
                        agg_result.get("added_count", 0),
                        agg_result.get("total_count", 0),
                    )
                except Exception as agg_exc:
                    logger.error("聚合优质 IP 到 tcp 质量池失败: %s", agg_exc)
            except Exception as exc:
                tcp_scan_registry.set_error(current_run_id, f"{exc}\n{traceback.format_exc()}")

        thread = Thread(target=worker, daemon=True)
        tcp_scan_registry.register(run_id, thread)
        thread.start()

    return jsonify({
        "success": True,
        "message": "TCP 扫描任务已创建",
        "run_ids": [item["run_id"] for item in created],
        "runs": created,
    })


@tcp_censor_bp.route("/runs/<run_id>", methods=["GET"])
def tcp_scan_run_detail(run_id: str):
    try:
        summary = read_result_summary(run_id, TCP_OUTPUT_ROOT)
        summary["is_running"] = tcp_scan_registry.is_running(run_id)
        summary["runtime_error"] = tcp_scan_registry.get_error(run_id)
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
    payload = request.get_json(silent=True) or {}
    cleanup = bool(payload.get("cleanup", False))
    stopped = stop_run(run_id, TCP_OUTPUT_ROOT, cleanup=cleanup)
    if not stopped and cleanup:
        cleaned = cleanup_run_artifacts(run_id, TCP_OUTPUT_ROOT)
        return jsonify({"success": cleaned, "message": "已清理任务产物" if cleaned else "No running process found"})
    return jsonify({"success": stopped, "message": "Stopping TCP scan" if stopped else "No running process found"})


@tcp_censor_bp.route("/runs/<run_id>/files/<path:filename>", methods=["GET"])
def tcp_scan_file_read(run_id: str, filename: str):
    try:
        return jsonify({"success": True, "file": read_run_file(run_id, filename, TCP_OUTPUT_ROOT)})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run file not found"}), 404
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@tcp_censor_bp.route("/runs/<run_id>/files/<path:filename>", methods=["PUT"])
def tcp_scan_file_write(run_id: str, filename: str):
    payload = request.get_json(silent=True) or {}
    content = str(payload.get("content", ""))
    try:
        result = write_run_file(run_id, filename, content, TCP_OUTPUT_ROOT)
        return jsonify({"success": True, "file": result, "message": "文件已保存"})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run file not found"}), 404
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@tcp_censor_bp.route("/state", methods=["GET"])
def tcp_scan_state_view():
    return jsonify({
        "success": True,
        "active_run_ids": tcp_scan_registry.active_run_ids(),
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
        min_amplification=_float_or(data.get("min_amplification"), 2.0),
        min_success_rate=_float_or(data.get("min_success_rate"), 50.0),
        network_interface=str(data.get("network_interface") or base.network_interface).strip(),
        output_root=TCP_OUTPUT_ROOT,
        dry_run=_bool(data.get("dry_run", base.dry_run)),
    )
    return validate_config(cfg, check_runtime=False)


def _prepare_run_metadata(config: ScanConfig) -> dict[str, Any]:
    run_dir = prepare_run(config)
    metadata = read_result_summary(run_dir.name, TCP_OUTPUT_ROOT)
    return metadata


def _resolve_ip_file(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() and path.exists():
        return path
    # 先在 TCP 专用目录找
    ip_root = repo_root() / "attack_resources" / "tcp" / "resources" / "ip_lists"
    candidate = ip_root / path.name
    if candidate.exists():
        return candidate
    # 再在共享目录找
    shared = repo_root() / "attack_resources" / "shared" / "ip_lists"
    candidate = shared / path.name
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


def _float_or(value, default: float) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default
