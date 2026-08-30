"""协议资源扫描路由的公共实现（dns / memcached / ntp 共用）。

三个协议的 ``routes.py`` 原本是结构性复制粘贴（约 430 行 × 3），本模块把
共同部分收敛为一个蓝图工厂 :func:`create_scan_blueprint`，各协议只需提供：

- 协议名、显示名、url 前缀、run_id 前缀、输出目录
- 扫描器与 ScanConfig 的构造（协议特定字段在此解析与校验）
- ``config -> dict`` 序列化（协议特定字段）
- 可选的额外路由（如 ``/query-types``、``/cmd-types``、``/probe-actions``）

对外契约保持不变：

- 蓝图名与 ``url_prefix`` 不变（``/api/dns-scan`` 等）
- 所有路由路径与响应字段不变
- 协议模块继续导出 ``<proto>_registry``、``<PROTO>_OUTPUT_ROOT``、
  ``_list_run_dirs``、``_read_run_file``、``_read_run_log``、
  ``_generate_run_id``、``_build_config_dict``、``_bool``、``_float_or``、
  ``_int_or``、``ScanConfig`` 等符号，供
  ``attack_resources.shared.attack_resource_api`` 直接导入（行为不变）
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Callable, Dict, List, Optional, Tuple

from flask import Blueprint, jsonify, request

from attack_resources.shared.ip_resource_catalog import (
    list_protocol_resources,
    resolve_protocol_resource_path,
)
from attack_resources.shared.qualified_pool import aggregate_quality_ips

logger = logging.getLogger(__name__)


# ── 运行注册表 ──────────────────────────────────────────


class ScanRunRegistry:
    """按 run_id 登记扫描器/线程/配置的线程安全注册表。"""

    def __init__(self) -> None:
        self.lock = Lock()
        self.scanners: Dict[str, Any] = {}
        self.threads: Dict[str, Thread] = {}
        self.errors: Dict[str, str] = {}
        self.configs: Dict[str, Any] = {}

    def register(self, run_id: str, scanner: Any, thread: Thread, config: Any) -> None:
        with self.lock:
            self.scanners[run_id] = scanner
            self.threads[run_id] = thread
            self.configs[run_id] = config
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

    def active_run_ids(self) -> List[str]:
        with self.lock:
            return [rid for rid, t in self.threads.items() if t.is_alive()]

    def get_scanner(self, run_id: str) -> Optional[Any]:
        with self.lock:
            return self.scanners.get(run_id)

    def get_config(self, run_id: str) -> Optional[Any]:
        with self.lock:
            return self.configs.get(run_id)

    def forget(self, run_ids: List[str]) -> None:
        with self.lock:
            for rid in run_ids:
                self.scanners.pop(rid, None)
                self.threads.pop(rid, None)
                self.errors.pop(rid, None)
                self.configs.pop(rid, None)


# ── 通用工具（协议模块 re-export 这些名字以保持兼容） ──────


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


def _list_ip_files(
    protocol: str, attack_resources_root: Path
) -> List[Dict[str, Any]]:
    """列出协议可用的候选 IP 文件。"""
    resources = list_protocol_resources(protocol, attack_resources_root)
    return [_normalize_resource(resource) for resource in resources]


def _resolve_ip_file(
    protocol: str, attack_resources_root: Path, value: str
) -> Optional[Path]:
    return resolve_protocol_resource_path(protocol, value, attack_resources_root)


def _generate_run_id(run_id_prefix: str) -> str:
    return datetime.now().strftime(f"{run_id_prefix}_%Y%m%d_%H%M%S")


def _list_run_dirs(
    output_root: Path, registry: ScanRunRegistry
) -> List[Dict[str, Any]]:
    """列出历史扫描运行。"""
    if not output_root.exists():
        return []
    runs: List[Dict[str, Any]] = []
    for d in sorted(output_root.iterdir(), reverse=True):
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
            "is_running": registry.is_running(run_id),
            "summary": summary,
            "status": stats.get("status", "completed" if summary.get("timestamp") else "idle"),
            "stage": stats.get("stage", ""),
            "qualified_count": summary.get("qualified_count", 0),
        })
    return runs


def _read_run_file(output_root: Path, run_id: str, filename: str) -> str:
    path = output_root / run_id / filename
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {filename}")
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_run_log(
    output_root: Path, registry: ScanRunRegistry, run_id: str, tail: int = 200
) -> str:
    """从扫描器内存读取日志（运行中），否则从文件读。"""
    scanner = registry.get_scanner(run_id)
    if scanner:
        return scanner.get_logs(tail)
    # 历史运行尝试读日志文件
    log_path = output_root / run_id / "pipeline.log"
    if log_path.exists():
        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(lines[-tail:])
    return ""


# ── 蓝图工厂 ────────────────────────────────────────────


@dataclass(frozen=True)
class ProtocolScanSpec:
    """描述一个协议扫描蓝图所需的协议特定信息。"""

    protocol: str
    display_name: str
    blueprint_name: str
    url_prefix: str
    run_id_prefix: str
    # 运行时动态读取输出目录（而非创建时快照），保证
    # ``mock.patch("...routes.<PROTO>_OUTPUT_ROOT", tmp)`` 这类测试补丁生效
    output_root_getter: Callable[[], Path]
    attack_resources_root: Path
    scanner_factory: Callable[[], Any]
    # (resolved_ip_file, output_dir, payload) -> (config, error_response|None)
    # error_response 为 (message, http_status) 元组时，start_scan 直接返回错误
    build_config: Callable[
        [Path, str, Dict[str, Any]],
        Tuple[Any, Optional[Tuple[str, int]]],
    ]
    config_to_dict: Callable[[Any], Dict[str, Any]]


def create_scan_blueprint(
    spec: ProtocolScanSpec,
    register_extra_routes: Optional[Callable[[Blueprint], None]] = None,
) -> Tuple[Blueprint, ScanRunRegistry]:
    """根据协议规格创建扫描蓝图与运行注册表。"""
    bp = Blueprint(spec.blueprint_name, __name__, url_prefix=spec.url_prefix)
    registry = ScanRunRegistry()

    # 每次请求动态读取输出目录，使测试对 <PROTO>_OUTPUT_ROOT 的 patch 生效
    def current_output_root() -> Path:
        return spec.output_root_getter()

    # ── 资源文件 ──────────────────────────────────────────

    @bp.route("/resources", methods=["GET"])
    def list_ip_resources():
        """列出可用的候选 IP 文件"""
        return jsonify({
            "success": True,
            "resources": _list_ip_files(spec.protocol, spec.attack_resources_root),
        })

    # ── 运行列表 / 详情 / 产物 ────────────────────────────

    @bp.route("/runs", methods=["GET"])
    def list_runs():
        """列出所有扫描运行"""
        output_root = current_output_root()
        runs = _list_run_dirs(output_root, registry)
        active = registry.active_run_ids()
        return jsonify({
            "success": True,
            "runs": runs,
            "active_run_ids": active,
            "running_count": len(active),
        })

    @bp.route("/runs/<run_id>", methods=["GET"])
    def get_run_detail(run_id: str):
        """获取运行详情"""
        output_root = current_output_root()
        scanner = registry.get_scanner(run_id)
        run_dir = output_root / run_id
        if scanner:
            stats = scanner.get_stats()
            is_running = registry.is_running(run_id)
        else:
            # 尝试从文件读取历史运行
            stats_path = output_root / run_id / "final_stats.json"
            summary_path = output_root / run_id / "scan_summary.json"
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

        runtime_error = registry.get_error(run_id) or str(stats.get("error") or "")

        # 产物文件
        artifacts = []
        if run_dir.exists():
            for f in sorted(run_dir.iterdir()):
                if f.is_file():
                    artifacts.append({"name": f.name, "size": f.stat().st_size})

        config = registry.get_config(run_id)
        config_dict = None
        if config:
            config_dict = spec.config_to_dict(config)
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

    @bp.route("/runs/<run_id>/logs", methods=["GET"])
    def get_run_logs(run_id: str):
        """获取运行日志"""
        output_root = current_output_root()
        tail = _int_or(request.args.get("tail", "200"), 200)
        try:
            return jsonify({
                "success": True,
                "log": _read_run_log(output_root, registry, run_id, tail),
            })
        except FileNotFoundError:
            return jsonify({"success": False, "message": "Run not found"}), 404

    @bp.route("/runs/<run_id>/stop", methods=["POST"])
    def stop_scan(run_id: str):
        """停止扫描"""
        scanner = registry.get_scanner(run_id)
        if scanner and scanner.is_running:
            scanner.stop()
            return jsonify({
                "success": True,
                "message": f"正在停止 {spec.display_name} 资源扫描 …",
            })
        return jsonify({"success": False, "message": "没有正在运行的扫描"})

    @bp.route("/runs/<run_id>/results", methods=["GET"])
    def get_run_results(run_id: str):
        """获取扫描结果（优质 IP 列表及各 IP 详情）"""
        output_root = current_output_root()
        scanner = registry.get_scanner(run_id)
        if scanner:
            qualified = scanner.get_qualified_ips()
            all_results = scanner.get_results(limit=500)
        else:
            # 从文件读
            ip_file = output_root / run_id / "qualified_ips.txt"
            qualified = []
            if ip_file.exists():
                qualified = [
                    line.strip()
                    for line in ip_file.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
            all_results = []
            csv_file = output_root / run_id / "scan_results.csv"
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

    @bp.route("/runs", methods=["DELETE"])
    def clear_runs():
        """清理非活跃的历史运行"""
        output_root = current_output_root()
        active = set(registry.active_run_ids())
        deleted: List[str] = []
        skipped: List[str] = []

        if output_root.exists():
            for d in sorted(output_root.iterdir()):
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

        registry.forget(deleted)
        return jsonify({
            "success": True,
            "message": f"已清除 {len(deleted)} 条历史记录",
            "deleted": deleted,
            "skipped": skipped,
        })

    @bp.route("/runs/<run_id>/files/<path:filename>", methods=["GET"])
    def get_run_file(run_id: str, filename: str):
        """读取运行产物文件"""
        output_root = current_output_root()
        try:
            content = _read_run_file(output_root, run_id, filename)
            return jsonify({"success": True, "content": content, "filename": filename})
        except FileNotFoundError:
            return jsonify({"success": False, "message": "文件不存在"}), 404

    @bp.route("/state", methods=["GET"])
    def scan_state():
        """当前活跃扫描状态"""
        return jsonify({
            "success": True,
            "active_run_ids": registry.active_run_ids(),
        })

    # ── 启动扫描 ──────────────────────────────────────────

    @bp.route("/runs", methods=["POST"])
    def start_scan():
        """启动一次协议资源扫描"""
        output_root = current_output_root()
        payload = request.get_json(silent=True) or {}

        ip_file = str(payload.get("ip_file") or "")
        if not ip_file:
            # 尝试从共享目录查找
            available = _list_ip_files(spec.protocol, spec.attack_resources_root)
            if not available:
                return jsonify({"success": False, "message": "没有可用的 IP 候选文件"}), 400
            ip_file = available[0]["path"]

        resolved_ip_file = _resolve_ip_file(
            spec.protocol, spec.attack_resources_root, ip_file
        )
        if resolved_ip_file is None or not resolved_ip_file.exists():
            return jsonify({"success": False, "message": f"IP 文件不存在: {ip_file}"}), 400

        run_id = _generate_run_id(spec.run_id_prefix)
        output_dir = str(output_root / run_id)

        config, error = spec.build_config(resolved_ip_file, output_dir, payload)
        if error is not None:
            message, status = error
            return jsonify({"success": False, "message": message}), status

        scanner = spec.scanner_factory()

        # 日志持久化
        os.makedirs(output_dir, exist_ok=True)
        log_path = os.path.join(output_dir, "pipeline.log")
        config_dict = spec.config_to_dict(config)

        def log_persister(msg: str):
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

        def scan_worker():
            try:
                scanner.run_scan(config, log_callback=log_persister)
                try:
                    task_qualified_ips_path = os.path.join(output_dir, "qualified_ips.txt")
                    agg_result = aggregate_quality_ips(spec.protocol, task_qualified_ips_path)
                    logger.info(
                        "已聚合 %d 个优质 IP 到 %s 质量池，总计 %d 个",
                        agg_result.get("added_count", 0),
                        spec.protocol,
                        agg_result.get("total_count", 0),
                    )
                except Exception as agg_exc:
                    logger.error("聚合优质 IP 到 %s 质量池失败: %s", spec.protocol, agg_exc)
            except Exception as exc:
                registry.set_error(run_id, f"{exc}\n{traceback.format_exc()}")
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
        registry.register(run_id, scanner, thread, config)
        thread.start()

        return jsonify({
            "success": True,
            "message": f"{spec.display_name} 资源扫描已启动",
            "run_id": run_id,
            "ip_file": os.path.basename(str(resolved_ip_file)),
            "config": config_dict,
            "total_ips": 0,
        })

    if register_extra_routes is not None:
        register_extra_routes(bp)

    return bp, registry
