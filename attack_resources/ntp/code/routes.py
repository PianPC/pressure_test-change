"""
NTP 攻击资源获取 - Flask Blueprint

路由前缀: /api/ntp-scan/
提供 NTP 放大率测量扫描的完整 API：
  - IP 资源文件管理
  - 扫描任务创建/停止/查询
  - 日志与产物读取
"""

from __future__ import annotations

import json
import logging
import os
import time
import traceback
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request

from attack_resources.shared.ip_resource_catalog import list_protocol_resources, resolve_protocol_resource_path
from attack_resources.shared.qualified_pool import aggregate_quality_ips

from attack_resources.ntp.code.ntp_resource_scanner import (
    NTPResourceScanner,
    ScanConfig,
    PROBE_ACTIONS,
)

ntp_scan_bp = Blueprint("ntp_scan", __name__, url_prefix="/api/ntp-scan")

logger = logging.getLogger(__name__)

# 路径常量
REPO_ROOT = Path(__file__).resolve().parents[3]  # pressure_test-change/
NTP_OUTPUT_ROOT = REPO_ROOT / "attack_resources" / "ntp" / "runs" / "ntp_scan"
NTP_RESOURCES_ROOT = REPO_ROOT / "attack_resources" / "ntp" / "resources"
SHARED_IP_LISTS = REPO_ROOT / "attack_resources" / "shared" / "ip_lists"

# 默认候选 IP 文件查找路径
# ???????IP ?????????
DEFAULT_IP_SEARCH_DIRS = [
    SHARED_IP_LISTS,
    NTP_RESOURCES_ROOT / "ip_lists",
]
ATTACK_RESOURCES_ROOT = REPO_ROOT / "attack_resources"


# ── 运行注册表 ──────────────────────────────────────────

class NtpScanRegistry:
    def __init__(self):
        self.lock = Lock()
        self.scanners: Dict[str, NTPResourceScanner] = {}
        self.threads: Dict[str, Thread] = {}
        self.errors: Dict[str, str] = {}
        self.configs: Dict[str, ScanConfig] = {}

    def register(self, run_id: str, scanner: NTPResourceScanner, thread: Thread, config: ScanConfig):
        with self.lock:
            self.scanners[run_id] = scanner
            self.threads[run_id] = thread
            self.configs[run_id] = config
            self.errors.pop(run_id, None)

    def set_error(self, run_id: str, error: str):
        with self.lock:
            self.errors[run_id] = error

    def get_error(self, run_id: str) -> str:
        with self.lock:
            return self.errors.get(run_id, "")

    def is_running(self, run_id: str) -> bool:
        with self.lock:
            thread = self.threads.get(run_id)
            return bool(thread and thread.is_alive())

    def active_run_ids(self) -> List[str]:
        with self.lock:
            return [rid for rid, t in self.threads.items() if t.is_alive()]

    def get_scanner(self, run_id: str) -> Optional[NTPResourceScanner]:
        with self.lock:
            return self.scanners.get(run_id)

    def get_config(self, run_id: str) -> Optional[ScanConfig]:
        with self.lock:
            return self.configs.get(run_id)

    def forget(self, run_ids: List[str]):
        with self.lock:
            for rid in run_ids:
                self.scanners.pop(rid, None)
                self.threads.pop(rid, None)
                self.errors.pop(rid, None)
                self.configs.pop(rid, None)


ntp_registry = NtpScanRegistry()


# ── 辅助函数 ────────────────────────────────────────────


def _list_ip_files(search_dirs: Optional[List[Path]] = None) -> List[Dict[str, Any]]:
    """????????IP ???????????????????????????????"""
    del search_dirs
    resources = list_protocol_resources("ntp", ATTACK_RESOURCES_ROOT)
    return [_normalize_resource(resource) for resource in resources]


def _resolve_ip_file(value: str) -> Path | None:
    return resolve_protocol_resource_path("ntp", value, ATTACK_RESOURCES_ROOT)


def _normalize_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": resource["id"],
        "name": resource["display_name"],
        "filename": resource["filename"],
        "path": resource["path"],
        "full_path": resource["full_path"],
        "entry_count": resource.get("entry_count", 0),
        "count": resource.get("count", 0),
        "bytes": resource.get("bytes", resource.get("size_bytes", 0)),
        "source": resource.get("source"),
        "source_name": resource.get("source_name"),
        "type": resource.get("type"),
        "protocols": resource.get("protocols", []),
        "updated_at": resource.get("updated_at"),
        "sub_dir": resource.get("sub_dir", ""),
        "location_label": resource.get("location_label"),
        "legacy": resource.get("legacy", False),
    }


def _generate_run_id() -> str:
    return datetime.now().strftime("ntp_%Y%m%d_%H%M%S")


def _build_config_dict(config: ScanConfig) -> Dict[str, Any]:
    return {
        "ip_file": os.path.basename(config.ip_file),
        "probe_action": config.probe_action,
        "timeout_sec": config.timeout_sec,
        "concurrency": config.concurrency,
        "min_amplification": config.min_amplification,
        "min_availability": config.min_availability,
        "max_ips": config.max_ips,
        "ntp_port": config.ntp_port,
    }


def _list_run_dirs() -> List[Dict[str, Any]]:
    """列出历史扫描运行"""
    if not NTP_OUTPUT_ROOT.exists():
        return []
    runs: List[Dict[str, Any]] = []
    for d in sorted(NTP_OUTPUT_ROOT.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        run_id = d.name
        summary_path = d / "scan_summary.json"
        summary = {}
        if summary_path.exists():
            try:
                with summary_path.open("r", encoding="utf-8") as f:
                    summary = json.load(f)
            except Exception:
                pass
        stats_path = d / "final_stats.json"
        stats = {}
        if stats_path.exists():
            try:
                with stats_path.open("r", encoding="utf-8") as f:
                    stats = json.load(f)
            except Exception:
                pass
        runs.append({
            "run_id": run_id,
            "is_running": ntp_registry.is_running(run_id),
            "summary": summary,
            "status": stats.get("status", "completed" if summary.get("timestamp") else "idle"),
            "stage": stats.get("stage", ""),
            "qualified_count": summary.get("qualified_count", 0),
        })
    return runs


def _read_run_file(run_id: str, filename: str) -> str:
    path = NTP_OUTPUT_ROOT / run_id / filename
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {filename}")
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_run_log(run_id: str, tail: int = 200) -> str:
    """从扫描器内存读取日志（运行中），否则从文件读"""
    scanner = ntp_registry.get_scanner(run_id)
    if scanner:
        return scanner.get_logs(tail)
    # 历史运行尝试读日志文件
    log_path = NTP_OUTPUT_ROOT / run_id / "pipeline.log"
    if log_path.exists():
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(lines[-tail:])
    return ""


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _float_or(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int_or(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ── API 路由 ────────────────────────────────────────────

@ntp_scan_bp.route("/resources", methods=["GET"])
def list_ip_resources():
    """列出可用的候选 IP 文件"""
    return jsonify({"success": True, "resources": _list_ip_files()})


@ntp_scan_bp.route("/probe-actions", methods=["GET"])
def probe_actions():
    """返回支持的探测动作"""
    return jsonify({
        "success": True,
        "actions": {key: val for key, val in PROBE_ACTIONS.items()},
    })


@ntp_scan_bp.route("/runs", methods=["GET"])
def list_runs():
    """列出所有扫描运行"""
    runs = _list_run_dirs()
    active = ntp_registry.active_run_ids()
    return jsonify({
        "success": True,
        "runs": runs,
        "active_run_ids": active,
        "running_count": len(active),
    })


@ntp_scan_bp.route("/runs", methods=["POST"])
def start_scan():
    """启动一次 NTP 资源扫描"""
    payload = request.get_json(silent=True) or {}

    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        # 尝试从共享目录查找
        available = _list_ip_files()
        if not available:
            return jsonify({"success": False, "message": "没有可用的 IP 候选文件"}), 400
        ip_file = available[0]["path"]

    resolved_ip_file = _resolve_ip_file(ip_file)
    if resolved_ip_file is None or not resolved_ip_file.exists():
        return jsonify({"success": False, "message": f"IP 文件不存在: {ip_file}"}), 400

    run_id = _generate_run_id()
    output_dir = str(NTP_OUTPUT_ROOT / run_id)

    probe_action = str(payload.get("probe_action", "both")).strip().lower()
    if probe_action not in PROBE_ACTIONS:
        probe_action = "both"

    config = ScanConfig(
        ip_file=str(resolved_ip_file),
        output_dir=output_dir,
        probe_action=probe_action,
        timeout_sec=_float_or(payload.get("timeout_sec"), 3.0),
        concurrency=_int_or(payload.get("concurrency"), 50),
        min_amplification=_float_or(payload.get("min_amplification"), 50.0),
        min_availability=_float_or(payload.get("min_availability"), 30.0),
        max_ips=_int_or(payload.get("max_ips"), 0),
    )

    scanner = NTPResourceScanner()

    # 日志持久化
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "pipeline.log")
    config_dict = _build_config_dict(config)

    def log_persister(msg: str):
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")

    def scan_worker():
        try:
            scanner.run_scan(config, log_callback=log_persister)
            try:
                task_qualified_ips_path = os.path.join(output_dir, "qualified_ips.txt")
                agg_result = aggregate_quality_ips("ntp", task_qualified_ips_path)
                logger.info(
                    "已聚合 %d 个优质 IP 到 ntp 质量池，总计 %d 个",
                    agg_result.get("added_count", 0),
                    agg_result.get("total_count", 0),
                )
            except Exception as agg_exc:
                logger.error("聚合优质 IP 到 ntp 质量池失败: %s", agg_exc)
        except Exception as exc:
            ntp_registry.set_error(run_id, f"{exc}\n{traceback.format_exc()}")
        finally:
            # 保存最终统计
            stats_file = os.path.join(output_dir, "final_stats.json")
            try:
                final_stats = scanner.get_stats()
                final_stats.setdefault("config", config_dict)
                with open(stats_file, "w", encoding="utf-8") as f:
                    json.dump(final_stats, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    thread = Thread(target=scan_worker, daemon=True)
    ntp_registry.register(run_id, scanner, thread, config)
    thread.start()

    return jsonify({
        "success": True,
        "message": "NTP 资源扫描已启动",
        "run_id": run_id,
        "ip_file": os.path.basename(str(resolved_ip_file)),
        "config": config_dict,
        "total_ips": 0,
    })


@ntp_scan_bp.route("/runs/<run_id>", methods=["GET"])
def get_run_detail(run_id: str):
    """获取运行详情"""
    scanner = ntp_registry.get_scanner(run_id)
    run_dir = NTP_OUTPUT_ROOT / run_id
    if scanner:
        stats = scanner.get_stats()
        is_running = ntp_registry.is_running(run_id)
    else:
        # 尝试从文件读取历史运行
        stats_path = NTP_OUTPUT_ROOT / run_id / "final_stats.json"
        summary_path = NTP_OUTPUT_ROOT / run_id / "scan_summary.json"
        stats = {}
        if stats_path.exists():
            try:
                stats = json.loads(stats_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                stats.update(summary)
            except Exception:
                pass
        is_running = False

    if run_dir.exists():
        log_path = run_dir / "pipeline.log"
        if log_path.exists():
            try:
                lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if lines:
                    stats.setdefault("log_tail", "\n".join(lines[-200:]))
            except Exception:
                pass

    runtime_error = ntp_registry.get_error(run_id) or str(stats.get("error") or "")

    # 产物文件
    artifacts = []
    if run_dir.exists():
        for f in sorted(run_dir.iterdir()):
            if f.is_file():
                artifacts.append({"name": f.name, "size": f.stat().st_size})

    config = ntp_registry.get_config(run_id)
    config_dict = None
    if config:
        config_dict = _build_config_dict(config)
    elif isinstance(stats.get("config"), dict):
        config_dict = stats.get("config")

    return jsonify({
        "success": True,
        "run_id": run_id,
        "is_running": is_running,
        "stats": stats,
        "config": config_dict,
        "artifacts": artifacts,
        "runtime_error": runtime_error,
    })


@ntp_scan_bp.route("/runs/<run_id>/logs", methods=["GET"])
def get_run_logs(run_id: str):
    """获取运行日志"""
    tail = _int_or(request.args.get("tail", "200"), 200)
    try:
        return jsonify({"success": True, "log": _read_run_log(run_id, tail)})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404


@ntp_scan_bp.route("/runs/<run_id>/stop", methods=["POST"])
def stop_scan(run_id: str):
    """停止扫描"""
    scanner = ntp_registry.get_scanner(run_id)
    if scanner and scanner.is_running:
        scanner.stop()
        return jsonify({"success": True, "message": "正在停止 NTP 资源扫描 …"})
    return jsonify({"success": False, "message": "没有正在运行的扫描"})


@ntp_scan_bp.route("/runs/<run_id>/results", methods=["GET"])
def get_run_results(run_id: str):
    """获取扫描结果（优质 IP 列表及各 IP 详情）"""
    scanner = ntp_registry.get_scanner(run_id)
    if scanner:
        qualified = scanner.get_qualified_ips()
        all_results = scanner.get_results(limit=500)
    else:
        # 从文件读
        ip_file = NTP_OUTPUT_ROOT / run_id / "qualified_ips.txt"
        qualified = []
        if ip_file.exists():
            qualified = [line.strip() for line in ip_file.read_text(encoding="utf-8").splitlines()
                         if line.strip() and not line.startswith("#")]
        all_results = []
        csv_file = NTP_OUTPUT_ROOT / run_id / "scan_results.csv"
        if csv_file.exists():
            import csv
            with csv_file.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                all_results = [row for row in reader]

    return jsonify({
        "success": True,
        "qualified_ips": qualified,
        "qualified_count": len(qualified),
        "results": all_results,
    })


@ntp_scan_bp.route("/runs", methods=["DELETE"])
def clear_runs():
    """清理非活跃的历史运行"""
    import shutil
    active = set(ntp_registry.active_run_ids())
    deleted: List[str] = []
    skipped: List[str] = []

    if NTP_OUTPUT_ROOT.exists():
        for d in sorted(NTP_OUTPUT_ROOT.iterdir()):
            if not d.is_dir():
                continue
            run_id = d.name
            if run_id in active:
                skipped.append(run_id)
                continue
            try:
                shutil.rmtree(str(d))
                deleted.append(run_id)
            except Exception:
                pass

    ntp_registry.forget(deleted)
    return jsonify({
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    })


@ntp_scan_bp.route("/runs/<run_id>/files/<path:filename>", methods=["GET"])
def get_run_file(run_id: str, filename: str):
    """读取运行产物文件"""
    try:
        content = _read_run_file(run_id, filename)
        return jsonify({"success": True, "content": content, "filename": filename})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "文件不存在"}), 404


@ntp_scan_bp.route("/state", methods=["GET"])
def scan_state():
    """当前活跃扫描状态"""
    return jsonify({
        "success": True,
        "active_run_ids": ntp_registry.active_run_ids(),
    })
