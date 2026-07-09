from __future__ import annotations

import csv
import json
import os
import shutil
import traceback
from dataclasses import replace
from pathlib import Path
from threading import Thread
from typing import Any

from flask import Blueprint, jsonify, request

from attack_resources.tcp.code.routes import (
    DEFAULT_CONFIG_PATH as TCP_DEFAULT_CONFIG_PATH,
    TCP_OUTPUT_ROOT,
    _bool as tcp_bool,
    _config_from_request as tcp_config_from_request,
    _prepare_run_metadata as tcp_prepare_run_metadata,
    cleanup_run_artifacts as tcp_cleanup_run_artifacts,
    preflight_check as tcp_preflight_check,
    tcp_scan_registry,
)
from attack_resources.tcp.code.tcp_censor_scan import (
    list_ip_resources as tcp_list_ip_resources,
    list_runs as tcp_list_runs,
    read_result_summary as tcp_read_result_summary,
    read_run_file as tcp_read_run_file,
    read_run_log as tcp_read_run_log,
    run_pipeline as tcp_run_pipeline,
    stop_run as tcp_stop_run,
    write_run_file as tcp_write_run_file,
)
from attack_resources.tcp.code.tcp_censor_scan.config import ConfigError, ScanConfig as TcpScanConfig
from attack_resources.memcached.code.memcached_resource_scanner import MemcachedResourceScanner, MEMCACHED_CMD_TYPES
from attack_resources.memcached.code.routes import (
    MEMCACHED_OUTPUT_ROOT,
    MEMCACHED_RESOURCES_ROOT,
    _bool as memcached_bool,
    _build_config_dict as memcached_build_config_dict,
    _float_or as memcached_float_or,
    _generate_run_id as memcached_generate_run_id,
    _int_or as memcached_int_or,
    _list_ip_files as memcached_list_ip_files,
    _list_run_dirs as memcached_list_run_dirs,
    _read_run_file as memcached_read_run_file,
    _read_run_log as memcached_read_run_log,
    memcached_registry,
    ScanConfig as MemcachedScanConfig,
)
from attack_resources.dns.code.dns_resource_scanner import DNSResourceScanner, DNS_TYPE_MAP, DEFAULT_TEST_DOMAINS
from attack_resources.dns.code.routes import (
    DNS_OUTPUT_ROOT,
    DNS_RESOURCES_ROOT,
    SHARED_IP_LISTS,
    _bool as dns_bool,
    _build_config_dict as dns_build_config_dict,
    _float_or as dns_float_or,
    _generate_run_id as dns_generate_run_id,
    _int_or as dns_int_or,
    _list_ip_files as dns_list_ip_files,
    _list_run_dirs as dns_list_run_dirs,
    _read_run_file as dns_read_run_file,
    _read_run_log as dns_read_run_log,
    dns_registry,
    ScanConfig as DnsScanConfig,
)
from attack_resources.memcached.code.memcached_resource_scanner import MemcachedResourceScanner, MEMCACHED_CMD_TYPES
from attack_resources.memcached.code.routes import (
    MEMCACHED_OUTPUT_ROOT,
    _bool as memcached_bool,
    _build_config_dict as memcached_build_config_dict,
    _float_or as memcached_float_or,
    _generate_run_id as memcached_generate_run_id,
    _int_or as memcached_int_or,
    _list_ip_files as memcached_list_ip_files,
    _list_run_dirs as memcached_list_run_dirs,
    _read_run_file as memcached_read_run_file,
    _read_run_log as memcached_read_run_log,
    memcached_registry,
    ScanConfig as MemcachedScanConfig,
)


attack_resource_bp = Blueprint("attack_resource", __name__, url_prefix="/api/attack-resource")

EDITABLE_TEXT_SUFFIXES = {".log", ".txt", ".csv", ".json"}
TCP_STAGE_ORDER = [
    ("prepare_zmap", "准备 ZMap"),
    ("run_zmap_scan", "执行 ZMap 扫描"),
    ("process_scan_csv", "处理扫描 CSV"),
    ("extract_ips", "提取 IP"),
    ("run_amplification_test", "执行放大测试"),
    ("analyze_amplification_log", "分析放大日志"),
]
DNS_STAGE_ORDER = [
    ("loading", "加载候选 IP"),
    ("scanning", "放大率测量"),
    ("filtering", "按阈值筛选"),
    ("saving", "保存结果"),
]
MEMCACHED_STAGE_ORDER = [
    ("loading", "加载候选 IP"),
    ("scanning", "执行 Memcached 探测"),
    ("filtering", "筛选高价值目标"),
    ("saving", "保存结果"),
]
MEMCACHED_STAGE_ORDER = [
    ("loading", "加载候选 IP"),
    ("scanning", "执行 Memcached 探测"),
    ("filtering", "筛选高价值目标"),
    ("saving", "保存结果"),
]


def _text_artifact_descriptor(name: str, size: int, editable: bool | None = None) -> dict[str, Any]:
    suffix = Path(name).suffix.lower()
    return {
        "name": name,
        "size": size,
        "editable": (suffix in EDITABLE_TEXT_SUFFIXES) if editable is None else editable,
        "kind": "db" if suffix == ".db" else "text",
    }


def _normalize_stage_status(status: str | None) -> str:
    if status in {"completed", "failed", "stopped", "running", "pending", "skipped"}:
        return status
    return "pending"


def _build_progress(current: int | None = None, total: int | None = None) -> dict[str, Any]:
    current_value = int(current or 0)
    total_value = int(total or 0)
    return {
        "current": current_value,
        "total": total_value,
        "label": f"{current_value}/{total_value}" if total_value else f"{current_value}/0",
    }


def _build_tcp_run_payload(run_id: str) -> dict[str, Any]:
    summary = tcp_read_result_summary(run_id, TCP_OUTPUT_ROOT)
    is_running = tcp_scan_registry.is_running(run_id)
    runtime_error = tcp_scan_registry.get_error(run_id) or summary.get("error", "")
    config = summary.get("config", {})
    stages = summary.get("stages", {})
    current_stage = summary.get("current_stage")
    completed_stage_count = sum(1 for stage, _ in TCP_STAGE_ORDER if stages.get(stage, {}).get("status") in {"completed", "skipped"})
    progress = _build_progress(completed_stage_count, len(TCP_STAGE_ORDER))
    normalized_stages = []
    for stage_key, stage_label in TCP_STAGE_ORDER:
        stage_state = stages.get(stage_key, {}).get("status")
        if not stage_state and current_stage == stage_key:
            stage_state = "running"
        normalized_stages.append({
            "key": stage_key,
            "label": stage_label,
            "status": _normalize_stage_status(stage_state),
        })

    files = summary.get("files", [])
    detail_items = [
        {"label": "当前阶段", "value": next((item["label"] for item in normalized_stages if item["key"] == current_stage), "-")},
        {"label": "开始时间", "value": summary.get("started_at") or "-"},
        {"label": "结束时间", "value": summary.get("ended_at") or "-"},
        {"label": "模拟运行", "value": "是" if config.get("dry_run") else "否"},
        {"label": "停止请求", "value": "已请求" if summary.get("stop_requested") else "未请求"},
        {"label": "失败原因", "value": runtime_error or "-"},
    ]

    return {
        "run_id": run_id,
        "proto": "tcp",
        "status": summary.get("status", "unknown"),
        "is_running": is_running,
        "started_at": summary.get("started_at"),
        "ended_at": summary.get("ended_at"),
        "current_stage": current_stage,
        "progress": progress,
        "config": config,
        "summary_stats": {
            "method": config.get("pkt_method") or "-",
            "target_host": config.get("target_host") or "-",
            "artifact_count": len(files),
        },
        "detail_items": detail_items,
        "stages": normalized_stages,
        "artifacts": [_text_artifact_descriptor(file["name"], file.get("bytes", 0)) for file in files],
        "result_preview": None,
        "runtime_error": runtime_error,
    }


def _build_tcp_runs_list() -> dict[str, Any]:
    runs = []
    for run in tcp_list_runs(TCP_OUTPUT_ROOT):
        run_id = run["run_id"]
        runs.append({
            "run_id": run_id,
            "proto": "tcp",
            "status": run.get("status", "unknown"),
            "is_running": tcp_scan_registry.is_running(run_id),
            "primary_text": run_id,
            "secondary_text": run.get("target_host") or "-",
            "badge_text": run.get("pkt_method") or "-",
        })
    active_run_ids = tcp_scan_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _tcp_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    methods = payload.get("pkt_methods") or [payload.get("pkt_method")]
    created: list[dict[str, Any]] = []
    try:
        configs = [tcp_config_from_request({**payload, "pkt_method": method}) for method in methods if method]
    except (ConfigError, ValueError) as exc:
        return {"success": False, "message": str(exc)}, 400

    for config in configs:
        if not config.dry_run:
            report = tcp_preflight_check(config)
            if not report["ok"]:
                return {"success": False, "message": "预检未通过", "report": report}, 400

    for config in configs:
        metadata = tcp_prepare_run_metadata(config)
        run_id = metadata["run_id"]
        created.append({"run_id": run_id, "pkt_method": config.pkt_method, "target_host": config.target_host})

        def worker(cfg: TcpScanConfig = config, current_run_id: str = run_id) -> None:
            try:
                tcp_run_pipeline(cfg, run_dir=TCP_OUTPUT_ROOT / current_run_id)
            except Exception as exc:  # pragma: no cover - defensive thread path
                tcp_scan_registry.set_error(current_run_id, f"{exc}\n{traceback.format_exc()}")

        thread = Thread(target=worker, daemon=True)
        tcp_scan_registry.register(run_id, thread)
        thread.start()

    return {
        "success": True,
        "message": "TCP 资源获取任务已创建",
        "run_ids": [item["run_id"] for item in created],
        "runs": created,
    }, 200


def _tcp_clear() -> dict[str, Any]:
    active_run_ids = set(tcp_scan_registry.active_run_ids())
    deleted: list[str] = []
    skipped: list[str] = []
    for run in tcp_list_runs(TCP_OUTPUT_ROOT):
        run_id = run.get("run_id")
        if not run_id:
            continue
        if run_id in active_run_ids:
            skipped.append(run_id)
            continue
        if tcp_cleanup_run_artifacts(run_id, TCP_OUTPUT_ROOT):
            deleted.append(run_id)
    tcp_scan_registry.forget(deleted)
    return {
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    }


def _build_dns_run_payload(run_id: str) -> dict[str, Any]:
    scanner = dns_registry.get_scanner(run_id)
    run_dir = DNS_OUTPUT_ROOT / run_id
    stats: dict[str, Any] = {}
    if scanner:
        stats = scanner.get_stats()
        is_running = dns_registry.is_running(run_id)
    else:
        stats_path = run_dir / "final_stats.json"
        summary_path = run_dir / "scan_summary.json"
        if stats_path.exists():
            try:
                stats = json.loads(stats_path.read_text(encoding="utf-8"))
            except Exception:
                stats = {}
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                stats.update(summary)
            except Exception:
                pass
        if run_dir.exists():
            log_path = run_dir / "pipeline.log"
            if log_path.exists():
                try:
                    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if lines:
                        stats.setdefault("log_tail", "\n".join(lines[-200:]))
                except Exception:
                    pass
        is_running = False

    runtime_error = dns_registry.get_error(run_id) or str(stats.get("error") or "")
    config = dns_registry.get_config(run_id)
    if config:
        config_dict = dns_build_config_dict(config)
    else:
        config_dict = stats.get("config") if isinstance(stats.get("config"), dict) else None
    config_dict = config_dict or {}

    current_stage = stats.get("current_stage") or stats.get("stage")
    normalized_stages = []
    stage_states = stats.get("stages", {})
    final_stage = stats.get("stage")
    for stage_key, stage_label in DNS_STAGE_ORDER:
        stage_status = stage_states.get(stage_key, {}).get("status")
        if not stage_status and is_running and current_stage == stage_key:
            stage_status = "running"
        if not stage_status and final_stage == "done":
            stage_status = "completed"
        normalized_stages.append({
            "key": stage_key,
            "label": stage_label,
            "status": _normalize_dns_stage_status(stage_status, final_stage, current_stage, stage_key),
        })

    artifacts = []
    if run_dir.exists():
        for file in sorted(run_dir.iterdir()):
            if file.is_file():
                artifacts.append(_text_artifact_descriptor(file.name, file.stat().st_size, editable=False))

    qualified_ips = _dns_get_qualified_ips(run_id, scanner)
    detail_items = [
        {"label": "当前阶段", "value": _dns_stage_status_label(stats.get("stage"), is_running)},
        {"label": "查询类型", "value": config_dict.get("query_type") or "-"},
        {"label": "DNSSEC", "value": "开启" if config_dict.get("use_dnssec") is True else ("关闭" if config_dict.get("use_dnssec") is False else "-")},
        {"label": "并发数", "value": config_dict.get("concurrency", "-")},
        {"label": "最小放大率", "value": config_dict.get("min_amplification", "-")},
        {"label": "最小可靠性", "value": config_dict.get("min_reliability", "-")},
        {"label": "优质 IP", "value": len(qualified_ips)},
        {"label": "失败原因", "value": runtime_error or "-"},
    ]

    return {
        "run_id": run_id,
        "proto": "dns",
        "status": stats.get("status", "idle"),
        "is_running": is_running,
        "started_at": stats.get("started_at"),
        "ended_at": stats.get("ended_at"),
        "current_stage": current_stage,
        "progress": _build_progress(stats.get("tested"), stats.get("total_tasks") or stats.get("total_ips")),
        "config": config_dict,
        "summary_stats": {
            "stage": (stats.get("stage") or "-").upper(),
            "qualified_count": len(qualified_ips),
            "tested": stats.get("tested", 0),
        },
        "detail_items": detail_items,
        "stages": normalized_stages,
        "artifacts": artifacts,
        "result_preview": {
            "type": "list",
            "title": "优质 IP",
            "items": qualified_ips[:5],
            "total": len(qualified_ips),
            "empty_text": "暂无优质 IP。完整结果可通过输出文件查看。",
        },
        "runtime_error": runtime_error,
    }


def _dns_stage_status_label(stage: str | None, is_running: bool) -> str:
    if stage == "done":
        return "已完成"
    if stage == "error":
        return "失败"
    if stage == "stopped":
        return "已停止"
    if stage == "saving":
        return "保存中" if is_running else "已保存"
    if stage == "filtering":
        return "筛选中" if is_running else "已筛选"
    if stage == "scanning":
        return "测量中" if is_running else "已测量"
    if stage == "loading":
        return "加载中" if is_running else "已加载"
    return "运行中" if is_running else "空闲"


def _normalize_dns_stage_status(stage_status: str | None, final_stage: str | None, current_stage: str | None, stage_key: str) -> str:
    if stage_status in {"completed", "failed", "stopped", "running"}:
        return stage_status
    if final_stage == "done":
        return "completed"
    if final_stage == "error" and current_stage == stage_key:
        return "failed"
    if final_stage == "stopped" and current_stage == stage_key:
        return "stopped"
    return "pending"


def _dns_get_qualified_ips(run_id: str, scanner: DNSResourceScanner | None) -> list[str]:
    if scanner:
        return scanner.get_qualified_ips()
    ip_file = DNS_OUTPUT_ROOT / run_id / "qualified_ips.txt"
    if not ip_file.exists():
        return []
    return [
        line.strip()
        for line in ip_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _build_dns_runs_list() -> dict[str, Any]:
    runs = []
    for run in dns_list_run_dirs():
        run_id = run["run_id"]
        runs.append({
            "run_id": run_id,
            "proto": "dns",
            "status": run.get("status", "idle"),
            "is_running": dns_registry.is_running(run_id),
            "primary_text": run_id,
            "secondary_text": f"优质: {run.get('qualified_count', 0)} IPs",
            "badge_text": (run.get("stage") or run.get("status") or "-").upper(),
        })
    active_run_ids = dns_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _dns_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        available = dns_list_ip_files()
        if not available:
            return {"success": False, "message": "没有可用的 IP 候选文件"}, 400
        ip_file = available[0]["path"]
    if not Path(ip_file).exists():
        return {"success": False, "message": f"IP 文件不存在: {ip_file}"}, 400

    domains_str = str(payload.get("test_domains", "")).strip()
    if domains_str:
        test_domains = [item.strip() for item in domains_str.replace(",", "\n").splitlines() if item.strip()]
    else:
        test_domains = DEFAULT_TEST_DOMAINS.copy()

    config = DnsScanConfig(
        ip_file=ip_file,
        output_dir=str(DNS_OUTPUT_ROOT / dns_generate_run_id()),
        test_domains=test_domains,
        query_type=str(payload.get("query_type", "TXT")).upper(),
        use_dnssec=dns_bool(payload.get("use_dnssec", True)),
        timeout_sec=dns_float_or(payload.get("timeout_sec"), 3.0),
        concurrency=dns_int_or(payload.get("concurrency"), 80),
        min_amplification=dns_float_or(payload.get("min_amplification"), 3.0),
        min_reliability=dns_float_or(payload.get("min_reliability"), 50.0),
        max_ips=dns_int_or(payload.get("max_ips"), 0),
    )
    if config.query_type not in DNS_TYPE_MAP:
        return {"success": False, "message": f"不支持的查询类型: {config.query_type}"}, 400

    run_id = Path(config.output_dir).name
    os.makedirs(config.output_dir, exist_ok=True)
    log_path = Path(config.output_dir) / "pipeline.log"
    config_dict = dns_build_config_dict(config)
    scanner = DNSResourceScanner()

    def log_persister(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    def scan_worker() -> None:
        try:
            scanner.run_scan(config, log_callback=log_persister)
        except Exception as exc:  # pragma: no cover - defensive thread path
            dns_registry.set_error(run_id, f"{exc}\n{traceback.format_exc()}")
        finally:
            stats_file = Path(config.output_dir) / "final_stats.json"
            try:
                final_stats = scanner.get_stats()
                final_stats.setdefault("config", config_dict)
                stats_file.write_text(json.dumps(final_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    thread = Thread(target=scan_worker, daemon=True)
    dns_registry.register(run_id, scanner, thread, config)
    thread.start()
    return {
        "success": True,
        "message": "DNS 资源获取任务已创建",
        "run_ids": [run_id],
        "runs": [{"run_id": run_id}],
    }, 200


def _dns_clear() -> dict[str, Any]:
    active = set(dns_registry.active_run_ids())
    deleted: list[str] = []
    skipped: list[str] = []
    if DNS_OUTPUT_ROOT.exists():
        for directory in sorted(DNS_OUTPUT_ROOT.iterdir()):
            if not directory.is_dir():
                continue
            run_id = directory.name
            if run_id in active:
                skipped.append(run_id)
                continue
            try:
                shutil.rmtree(str(directory))
                deleted.append(run_id)
            except Exception:
                pass
    dns_registry.forget(deleted)
    return {
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    }


# ── Memcached 构建函数 ────────────────────────────────

def _build_memcached_run_payload(run_id: str) -> dict[str, Any]:
    scanner = memcached_registry.get_scanner(run_id)
    run_dir = MEMCACHED_OUTPUT_ROOT / run_id
    stats: dict[str, Any] = {}
    if scanner:
        stats = scanner.get_stats()
        is_running = memcached_registry.is_running(run_id)
    else:
        stats_path = run_dir / "final_stats.json"
        summary_path = run_dir / "scan_summary.json"
        if stats_path.exists():
            try:
                stats = json.loads(stats_path.read_text(encoding="utf-8"))
            except Exception:
                stats = {}
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                stats.update(summary)
            except Exception:
                pass
        if run_dir.exists():
            log_path = run_dir / "pipeline.log"
            if log_path.exists():
                try:
                    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if lines:
                        stats.setdefault("log_tail", "\n".join(lines[-200:]))
                except Exception:
                    pass
        is_running = False

    runtime_error = memcached_registry.get_error(run_id) or str(stats.get("error") or "")
    config = memcached_registry.get_config(run_id)
    if config:
        config_dict = memcached_build_config_dict(config)
    else:
        config_dict = stats.get("config") if isinstance(stats.get("config"), dict) else None
    config_dict = config_dict or {}

    current_stage = stats.get("current_stage") or stats.get("stage")
    normalized_stages = []
    stage_states = stats.get("stages", {})
    final_stage = stats.get("stage")
    for stage_key, stage_label in MEMCACHED_STAGE_ORDER:
        stage_status = stage_states.get(stage_key, {}).get("status")
        if not stage_status and is_running and current_stage == stage_key:
            stage_status = "running"
        if not stage_status and final_stage == "done":
            stage_status = "completed"
        normalized_stages.append({
            "key": stage_key,
            "label": stage_label,
            "status": _normalize_memcached_stage_status(stage_status, final_stage, current_stage, stage_key),
        })

    artifacts = []
    if run_dir.exists():
        for file in sorted(run_dir.iterdir()):
            if file.is_file():
                artifacts.append(_text_artifact_descriptor(file.name, file.stat().st_size, editable=False))

    qualified_ips = _memcached_get_qualified_ips(run_id, scanner)
    detail_items = [
        {"label": "当前阶段", "value": _memcached_stage_status_label(stats.get("stage"), is_running)},
        {"label": "命令类型", "value": config_dict.get("cmd_type") or "-"},
        {"label": "数据大小", "value": f"{config_dict.get('data_size_kb', '-')}KB" if config_dict.get("data_size_kb") else "-"},
        {"label": "并发数", "value": config_dict.get("concurrency", "-")},
        {"label": "最小放大率", "value": config_dict.get("min_amplification", "-")},
        {"label": "最小可靠性", "value": config_dict.get("min_reliability", "-")},
        {"label": "优质 IP", "value": len(qualified_ips)},
        {"label": "失败原因", "value": runtime_error or "-"},
    ]

    return {
        "run_id": run_id,
        "proto": "memcached",
        "status": stats.get("status", "idle"),
        "is_running": is_running,
        "started_at": stats.get("started_at"),
        "ended_at": stats.get("ended_at"),
        "current_stage": current_stage,
        "progress": _build_progress(stats.get("tested"), stats.get("total_ips")),
        "config": config_dict,
        "summary_stats": {
            "stage": (stats.get("stage") or "-").upper(),
            "qualified_count": len(qualified_ips),
            "tested": stats.get("tested", 0),
        },
        "detail_items": detail_items,
        "stages": normalized_stages,
        "artifacts": artifacts,
        "result_preview": {
            "type": "list",
            "title": "优质 IP",
            "items": qualified_ips[:5],
            "total": len(qualified_ips),
            "empty_text": "暂无优质 IP。完整结果可通过输出文件查看。",
        },
        "runtime_error": runtime_error,
    }


def _memcached_stage_status_label(stage: str | None, is_running: bool) -> str:
    if stage == "done":
        return "已完成"
    if stage == "error":
        return "失败"
    if stage == "stopped":
        return "已停止"
    if stage == "saving":
        return "保存中" if is_running else "已保存"
    if stage == "filtering":
        return "筛选中" if is_running else "已筛选"
    if stage == "scanning":
        return "探测中" if is_running else "已探测"
    if stage == "loading":
        return "加载中" if is_running else "已加载"
    return "运行中" if is_running else "空闲"


def _normalize_memcached_stage_status(stage_status: str | None, final_stage: str | None, current_stage: str | None, stage_key: str) -> str:
    if stage_status in {"completed", "failed", "stopped", "running"}:
        return stage_status
    if final_stage == "done":
        return "completed"
    if final_stage == "error" and current_stage == stage_key:
        return "failed"
    if final_stage == "stopped" and current_stage == stage_key:
        return "stopped"
    return "pending"


def _memcached_get_qualified_ips(run_id: str, scanner: MemcachedResourceScanner | None) -> list[str]:
    if scanner:
        return scanner.get_qualified_ips()
    ip_file = MEMCACHED_OUTPUT_ROOT / run_id / "qualified_ips.txt"
    if not ip_file.exists():
        return []
    return [
        line.strip()
        for line in ip_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _build_memcached_runs_list() -> dict[str, Any]:
    runs = []
    for run in memcached_list_run_dirs():
        run_id = run["run_id"]
        runs.append({
            "run_id": run_id,
            "proto": "memcached",
            "status": run.get("status", "idle"),
            "is_running": memcached_registry.is_running(run_id),
            "primary_text": run_id,
            "secondary_text": f"优质: {run.get('qualified_count', 0)} IPs",
            "badge_text": (run.get("stage") or run.get("status") or "-").upper(),
        })
    active_run_ids = memcached_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _memcached_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        available = memcached_list_ip_files()
        if not available:
            return {"success": False, "message": "没有可用的 IP 候选文件"}, 400
        ip_file = available[0]["path"]
    if not Path(ip_file).exists():
        return {"success": False, "message": f"IP 文件不存在: {ip_file}"}, 400

    config = MemcachedScanConfig(
        ip_file=ip_file,
        output_dir=str(MEMCACHED_OUTPUT_ROOT / memcached_generate_run_id()),
        cmd_type=str(payload.get("cmd_type", "get")).lower(),
        data_size_kb=memcached_int_or(payload.get("data_size_kb"), 300),
        timeout_sec=memcached_float_or(payload.get("timeout_sec"), 3.0),
        concurrency=memcached_int_or(payload.get("concurrency"), 50),
        min_amplification=memcached_float_or(payload.get("min_amplification"), 10.0),
        min_reliability=memcached_float_or(payload.get("min_reliability"), 50.0),
        max_ips=memcached_int_or(payload.get("max_ips"), 0),
        memcached_port=memcached_int_or(payload.get("memcached_port"), 11211),
    )
    if config.cmd_type not in MEMCACHED_CMD_TYPES:
        return {"success": False, "message": f"不支持的命令类型: {config.cmd_type}"}, 400

    run_id = Path(config.output_dir).name
    os.makedirs(config.output_dir, exist_ok=True)
    log_path = Path(config.output_dir) / "pipeline.log"
    config_dict = memcached_build_config_dict(config)
    scanner = MemcachedResourceScanner()

    def log_persister(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    def scan_worker() -> None:
        try:
            scanner.run_scan(config, log_callback=log_persister)
        except Exception as exc:  # pragma: no cover - defensive thread path
            memcached_registry.set_error(run_id, f"{exc}\n{traceback.format_exc()}")
        finally:
            stats_file = Path(config.output_dir) / "final_stats.json"
            try:
                final_stats = scanner.get_stats()
                final_stats.setdefault("config", config_dict)
                stats_file.write_text(json.dumps(final_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    thread = Thread(target=scan_worker, daemon=True)
    memcached_registry.register(run_id, scanner, thread, config)
    thread.start()
    return {
        "success": True,
        "message": "Memcached 资源获取任务已创建",
        "run_ids": [run_id],
        "runs": [{"run_id": run_id}],
    }, 200


def _memcached_clear() -> dict[str, Any]:
    active = set(memcached_registry.active_run_ids())
    deleted: list[str] = []
    skipped: list[str] = []
    if MEMCACHED_OUTPUT_ROOT.exists():
        for directory in sorted(MEMCACHED_OUTPUT_ROOT.iterdir()):
            if not directory.is_dir():
                continue
            run_id = directory.name
            if run_id in active:
                skipped.append(run_id)
                continue
            try:
                shutil.rmtree(str(directory))
                deleted.append(run_id)
            except Exception:
                pass
    memcached_registry.forget(deleted)
    return {
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    }


class _ProtoAdapter:
    def __init__(self, proto: str):
        self.proto = proto

    def list_resources(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_runs(self) -> dict[str, Any]:
        raise NotImplementedError

    def start_run(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        raise NotImplementedError

    def clear_runs(self) -> dict[str, Any]:
        raise NotImplementedError

    def get_run(self, run_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def get_logs(self, run_id: str, tail: int) -> str:
        raise NotImplementedError

    def stop_run(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def get_results(self, run_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def read_file(self, run_id: str, filename: str) -> dict[str, Any]:
        raise NotImplementedError

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        raise NotImplementedError


class TcpAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("tcp")

    def list_resources(self) -> list[dict[str, Any]]:
        return tcp_list_ip_resources()

    def list_runs(self) -> dict[str, Any]:
        return _build_tcp_runs_list()

    def start_run(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        return _tcp_start(payload)

    def clear_runs(self) -> dict[str, Any]:
        return _tcp_clear()

    def get_run(self, run_id: str) -> dict[str, Any]:
        return _build_tcp_run_payload(run_id)

    def get_logs(self, run_id: str, tail: int) -> str:
        return tcp_read_run_log(run_id, "pipeline.log", TCP_OUTPUT_ROOT, tail)

    def stop_run(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        cleanup = bool(payload.get("cleanup", False))
        stopped = tcp_stop_run(run_id, TCP_OUTPUT_ROOT, cleanup=cleanup)
        if not stopped and cleanup:
            cleaned = tcp_cleanup_run_artifacts(run_id, TCP_OUTPUT_ROOT)
            return {"success": cleaned, "message": "已清理任务产物" if cleaned else "No running process found"}
        return {"success": stopped, "message": "Stopping TCP scan" if stopped else "No running process found"}

    def get_results(self, run_id: str) -> dict[str, Any]:
        run = _build_tcp_run_payload(run_id)
        return {
            "success": True,
            "result_preview": run.get("result_preview"),
            "artifacts": run.get("artifacts", []),
        }

    def read_file(self, run_id: str, filename: str) -> dict[str, Any]:
        return tcp_read_run_file(run_id, filename, TCP_OUTPUT_ROOT)

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        return tcp_write_run_file(run_id, filename, content, TCP_OUTPUT_ROOT)


class DnsAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("dns")

    def list_resources(self) -> list[dict[str, Any]]:
        return dns_list_ip_files()

    def list_runs(self) -> dict[str, Any]:
        return _build_dns_runs_list()

    def start_run(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        return _dns_start(payload)

    def clear_runs(self) -> dict[str, Any]:
        return _dns_clear()

    def get_run(self, run_id: str) -> dict[str, Any]:
        return _build_dns_run_payload(run_id)

    def get_logs(self, run_id: str, tail: int) -> str:
        return dns_read_run_log(run_id, tail)

    def stop_run(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        scanner = dns_registry.get_scanner(run_id)
        if scanner and scanner.is_running:
            scanner.stop()
            return {"success": True, "message": "正在停止 DNS 资源扫描…"}
        return {"success": False, "message": "没有正在运行的扫描"}

    def get_results(self, run_id: str) -> dict[str, Any]:
        scanner = dns_registry.get_scanner(run_id)
        qualified = _dns_get_qualified_ips(run_id, scanner)
        if scanner:
            results = scanner.get_results(limit=500)
        else:
            csv_file = DNS_OUTPUT_ROOT / run_id / "scan_results.csv"
            results = []
            if csv_file.exists():
                with csv_file.open("r", encoding="utf-8") as handle:
                    reader = csv.DictReader(handle)
                    results = [row for row in reader]
        return {
            "success": True,
            "qualified_ips": qualified,
            "qualified_count": len(qualified),
            "results": results,
        }

    def read_file(self, run_id: str, filename: str) -> dict[str, Any]:
        return {
            "name": filename,
            "path": str(DNS_OUTPUT_ROOT / run_id / filename),
            "type": "text",
            "editable": False,
            "content": dns_read_run_file(run_id, filename),
        }

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        raise ValueError("File type is not editable")


class MemcachedAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("memcached")

    def list_resources(self) -> list[dict[str, Any]]:
        return memcached_list_ip_files()

    def list_runs(self) -> dict[str, Any]:
        return _build_memcached_runs_list()

    def start_run(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        return _memcached_start(payload)

    def clear_runs(self) -> dict[str, Any]:
        return _memcached_clear()

    def get_run(self, run_id: str) -> dict[str, Any]:
        return _build_memcached_run_payload(run_id)

    def get_logs(self, run_id: str, tail: int) -> str:
        return memcached_read_run_log(run_id, tail)

    def stop_run(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        scanner = memcached_registry.get_scanner(run_id)
        if scanner and scanner.is_running:
            scanner.stop()
            return {"success": True, "message": "正在停止 Memcached 资源扫描…"}
        return {"success": False, "message": "没有正在运行的扫描"}

    def get_results(self, run_id: str) -> dict[str, Any]:
        scanner = memcached_registry.get_scanner(run_id)
        qualified = _memcached_get_qualified_ips(run_id, scanner)
        if scanner:
            results = scanner.get_results(limit=500)
        else:
            csv_file = MEMCACHED_OUTPUT_ROOT / run_id / "scan_results.csv"
            results = []
            if csv_file.exists():
                with csv_file.open("r", encoding="utf-8") as handle:
                    reader = csv.DictReader(handle)
                    results = [row for row in reader]
        return {
            "success": True,
            "qualified_ips": qualified,
            "qualified_count": len(qualified),
            "results": results,
        }

    def read_file(self, run_id: str, filename: str) -> dict[str, Any]:
        return {
            "name": filename,
            "path": str(MEMCACHED_OUTPUT_ROOT / run_id / filename),
            "type": "text",
            "editable": False,
            "content": memcached_read_run_file(run_id, filename),
        }

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        raise ValueError("File type is not editable")


def _build_memcached_run_payload(run_id: str) -> dict[str, Any]:
    scanner = memcached_registry.get_scanner(run_id)
    run_dir = MEMCACHED_OUTPUT_ROOT / run_id
    stats: dict[str, Any] = {}
    if scanner:
        stats = scanner.get_stats()
        is_running = memcached_registry.is_running(run_id)
    else:
        stats_path = run_dir / "final_stats.json"
        summary_path = run_dir / "scan_summary.json"
        if stats_path.exists():
            try:
                stats = json.loads(stats_path.read_text(encoding="utf-8"))
            except Exception:
                stats = {}
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                stats.update(summary)
            except Exception:
                pass
        if run_dir.exists():
            log_path = run_dir / "pipeline.log"
            if log_path.exists():
                try:
                    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if lines:
                        stats.setdefault("log_tail", "\n".join(lines[-200:]))
                except Exception:
                    pass
        is_running = False

    runtime_error = memcached_registry.get_error(run_id) or str(stats.get("error") or "")
    config = memcached_registry.get_config(run_id)
    if config:
        config_dict = memcached_build_config_dict(config)
    else:
        config_dict = stats.get("config") if isinstance(stats.get("config"), dict) else None
    config_dict = config_dict or {}

    current_stage = stats.get("current_stage") or stats.get("stage")
    normalized_stages = []
    stage_states = stats.get("stages", {})
    final_stage = stats.get("stage")
    for stage_key, stage_label in MEMCACHED_STAGE_ORDER:
        stage_status = stage_states.get(stage_key, {}).get("status")
        if not stage_status and is_running and current_stage == stage_key:
            stage_status = "running"
        if not stage_status and final_stage == "done":
            stage_status = "completed"
        normalized_stages.append({
            "key": stage_key,
            "label": stage_label,
            "status": _normalize_memcached_stage_status(stage_status, final_stage, current_stage, stage_key),
        })

    artifacts = []
    if run_dir.exists():
        for file in sorted(run_dir.iterdir()):
            if file.is_file():
                artifacts.append(_text_artifact_descriptor(file.name, file.stat().st_size, editable=False))

    qualified_ips = _memcached_get_qualified_ips(run_id, scanner)
    detail_items = [
        {"label": "当前阶段", "value": _memcached_stage_status_label(stats.get("stage"), is_running)},
        {"label": "命令类型", "value": config_dict.get("cmd_type") or "-"},
        {"label": "数据大小", "value": f"{config_dict.get('data_size_kb', '-')} KB" if config_dict.get("data_size_kb") else "-"},
        {"label": "并发数", "value": config_dict.get("concurrency", "-")},
        {"label": "最小放大率", "value": config_dict.get("min_amplification", "-")},
        {"label": "最小可靠性", "value": config_dict.get("min_reliability", "-")},
        {"label": "优质 IP", "value": len(qualified_ips)},
        {"label": "失败原因", "value": runtime_error or "-"},
    ]

    return {
        "run_id": run_id,
        "proto": "memcached",
        "status": stats.get("status", "idle"),
        "is_running": is_running,
        "started_at": stats.get("started_at"),
        "ended_at": stats.get("ended_at"),
        "current_stage": current_stage,
        "progress": _build_progress(stats.get("tested"), stats.get("total_tasks") or stats.get("total_ips")),
        "config": config_dict,
        "summary_stats": {
            "stage": (stats.get("stage") or "-").upper(),
            "qualified_count": len(qualified_ips),
            "tested": stats.get("tested", 0),
        },
        "detail_items": detail_items,
        "stages": normalized_stages,
        "artifacts": artifacts,
        "result_preview": {
            "type": "list",
            "title": "优质 IP",
            "items": qualified_ips[:5],
            "total": len(qualified_ips),
            "empty_text": "暂无优质 IP。完整结果可通过输出文件查看。",
        },
        "runtime_error": runtime_error,
    }


def _memcached_stage_status_label(stage: str | None, is_running: bool) -> str:
    if stage == "done":
        return "已完成"
    if stage == "error":
        return "失败"
    if stage == "stopped":
        return "已停止"
    if stage == "saving":
        return "保存中" if is_running else "已保存"
    if stage == "filtering":
        return "筛选中" if is_running else "已筛选"
    if stage == "scanning":
        return "探测中" if is_running else "已探测"
    if stage == "loading":
        return "加载中" if is_running else "已加载"
    return "运行中" if is_running else "空闲"


def _normalize_memcached_stage_status(stage_status: str | None, final_stage: str | None, current_stage: str | None, stage_key: str) -> str:
    if stage_status in {"completed", "failed", "stopped", "running"}:
        return stage_status
    if final_stage == "done":
        return "completed"
    if final_stage == "error" and current_stage == stage_key:
        return "failed"
    if final_stage == "stopped" and current_stage == stage_key:
        return "stopped"
    return "pending"


def _memcached_get_qualified_ips(run_id: str, scanner: MemcachedResourceScanner | None) -> list[str]:
    if scanner:
        return scanner.get_qualified_ips()
    ip_file = MEMCACHED_OUTPUT_ROOT / run_id / "qualified_ips.txt"
    if not ip_file.exists():
        return []
    return [
        line.strip()
        for line in ip_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _build_memcached_runs_list() -> dict[str, Any]:
    runs = []
    for run in memcached_list_run_dirs():
        run_id = run["run_id"]
        runs.append({
            "run_id": run_id,
            "proto": "memcached",
            "status": run.get("status", "idle"),
            "is_running": memcached_registry.is_running(run_id),
            "primary_text": run_id,
            "secondary_text": f"优质: {run.get('qualified_count', 0)} IPs",
            "badge_text": (run.get("stage") or run.get("status") or "-").upper(),
        })
    active_run_ids = memcached_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _memcached_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        available = memcached_list_ip_files()
        if not available:
            return {"success": False, "message": "没有可用的 IP 候选文件"}, 400
        ip_file = available[0]["path"]
    if not Path(ip_file).exists():
        return {"success": False, "message": f"IP 文件不存在: {ip_file}"}, 400

    cmd_type = str(payload.get("cmd_type", "get")).strip().lower()
    if cmd_type not in MEMCACHED_CMD_TYPES:
        cmd_type = "get"

    config = MemcachedScanConfig(
        ip_file=ip_file,
        output_dir=str(MEMCACHED_OUTPUT_ROOT / memcached_generate_run_id()),
        cmd_type=cmd_type,
        data_size_kb=memcached_int_or(payload.get("data_size_kb"), 300),
        timeout_sec=memcached_float_or(payload.get("timeout_sec"), 3.0),
        concurrency=memcached_int_or(payload.get("concurrency"), 50),
        min_amplification=memcached_float_or(payload.get("min_amplification"), 10.0),
        min_reliability=memcached_float_or(payload.get("min_reliability"), 50.0),
        max_ips=memcached_int_or(payload.get("max_ips"), 0),
    )

    run_id = Path(config.output_dir).name
    os.makedirs(config.output_dir, exist_ok=True)
    log_path = Path(config.output_dir) / "pipeline.log"
    config_dict = memcached_build_config_dict(config)
    scanner = MemcachedResourceScanner()

    def log_persister(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    def scan_worker() -> None:
        try:
            scanner.run_scan(config, log_callback=log_persister)
        except Exception as exc:  # pragma: no cover - defensive thread path
            memcached_registry.set_error(run_id, f"{exc}\n{traceback.format_exc()}")
        finally:
            stats_file = Path(config.output_dir) / "final_stats.json"
            try:
                final_stats = scanner.get_stats()
                final_stats.setdefault("config", config_dict)
                stats_file.write_text(json.dumps(final_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    thread = Thread(target=scan_worker, daemon=True)
    memcached_registry.register(run_id, scanner, thread, config)
    thread.start()
    return {
        "success": True,
        "message": "Memcached 资源获取任务已创建",
        "run_ids": [run_id],
        "runs": [{"run_id": run_id}],
    }, 200


def _memcached_clear() -> dict[str, Any]:
    active = set(memcached_registry.active_run_ids())
    deleted: list[str] = []
    skipped: list[str] = []
    if MEMCACHED_OUTPUT_ROOT.exists():
        for directory in sorted(MEMCACHED_OUTPUT_ROOT.iterdir()):
            if not directory.is_dir():
                continue
            run_id = directory.name
            if run_id in active:
                skipped.append(run_id)
                continue
            try:
                shutil.rmtree(str(directory))
                deleted.append(run_id)
            except Exception:
                pass
    memcached_registry.forget(deleted)
    return {
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    }


class MemcachedAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("memcached")

    def list_resources(self) -> list[dict[str, Any]]:
        return memcached_list_ip_files()

    def list_runs(self) -> dict[str, Any]:
        return _build_memcached_runs_list()

    def start_run(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        return _memcached_start(payload)

    def clear_runs(self) -> dict[str, Any]:
        return _memcached_clear()

    def get_run(self, run_id: str) -> dict[str, Any]:
        return _build_memcached_run_payload(run_id)

    def get_logs(self, run_id: str, tail: int) -> str:
        return memcached_read_run_log(run_id, tail)

    def stop_run(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        scanner = memcached_registry.get_scanner(run_id)
        if scanner and scanner.is_running:
            scanner.stop()
            return {"success": True, "message": "正在停止 Memcached 资源扫描…"}
        return {"success": False, "message": "没有正在运行的扫描"}

    def get_results(self, run_id: str) -> dict[str, Any]:
        scanner = memcached_registry.get_scanner(run_id)
        qualified = _memcached_get_qualified_ips(run_id, scanner)
        if scanner:
            results = scanner.get_results(limit=500)
        else:
            csv_file = MEMCACHED_OUTPUT_ROOT / run_id / "scan_results.csv"
            results = []
            if csv_file.exists():
                with csv_file.open("r", encoding="utf-8") as handle:
                    reader = csv.DictReader(handle)
                    results = [row for row in reader]
        return {
            "success": True,
            "qualified_ips": qualified,
            "qualified_count": len(qualified),
            "results": results,
        }

    def read_file(self, run_id: str, filename: str) -> dict[str, Any]:
        return {
            "name": filename,
            "path": str(MEMCACHED_OUTPUT_ROOT / run_id / filename),
            "type": "text",
            "editable": False,
            "content": memcached_read_run_file(run_id, filename),
        }

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        raise ValueError("File type is not editable")


ADAPTERS: dict[str, _ProtoAdapter] = {
    "tcp": TcpAdapter(),
    "dns": DnsAdapter(),
    "memcached": MemcachedAdapter(),
}


def _get_adapter(proto: str) -> _ProtoAdapter:
    adapter = ADAPTERS.get(proto)
    if not adapter:
        raise KeyError(proto)
    return adapter


@attack_resource_bp.route("/<proto>/resources", methods=["GET"])
def attack_resource_resources(proto: str):
    try:
        return jsonify({"success": True, "resources": _get_adapter(proto).list_resources()})
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501


@attack_resource_bp.route("/<proto>/runs", methods=["GET"])
def attack_resource_runs(proto: str):
    try:
        return jsonify({"success": True, **_get_adapter(proto).list_runs()})
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501


@attack_resource_bp.route("/<proto>/runs", methods=["POST"])
def attack_resource_start(proto: str):
    try:
        payload = request.get_json(silent=True) or {}
        body, status = _get_adapter(proto).start_run(payload)
        return jsonify(body), status
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501


@attack_resource_bp.route("/<proto>/runs", methods=["DELETE"])
def attack_resource_clear(proto: str):
    try:
        return jsonify(_get_adapter(proto).clear_runs())
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501


@attack_resource_bp.route("/<proto>/runs/<run_id>", methods=["GET"])
def attack_resource_run_detail(proto: str, run_id: str):
    try:
        return jsonify({"success": True, "run": _get_adapter(proto).get_run(run_id)})
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404


@attack_resource_bp.route("/<proto>/runs/<run_id>/logs", methods=["GET"])
def attack_resource_logs(proto: str, run_id: str):
    try:
        tail = int(request.args.get("tail", "200"))
    except ValueError:
        tail = 200
    try:
        return jsonify({"success": True, "log": _get_adapter(proto).get_logs(run_id, tail)})
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404


@attack_resource_bp.route("/<proto>/runs/<run_id>/stop", methods=["POST"])
def attack_resource_stop(proto: str, run_id: str):
    try:
        payload = request.get_json(silent=True) or {}
        return jsonify(_get_adapter(proto).stop_run(run_id, payload))
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501


@attack_resource_bp.route("/<proto>/runs/<run_id>/results", methods=["GET"])
def attack_resource_results(proto: str, run_id: str):
    try:
        return jsonify(_get_adapter(proto).get_results(run_id))
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404


@attack_resource_bp.route("/<proto>/runs/<run_id>/files/<path:filename>", methods=["GET"])
def attack_resource_file_read(proto: str, run_id: str, filename: str):
    try:
        return jsonify({"success": True, "file": _get_adapter(proto).read_file(run_id, filename)})
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run file not found"}), 404
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@attack_resource_bp.route("/<proto>/runs/<run_id>/files/<path:filename>", methods=["PUT"])
def attack_resource_file_write(proto: str, run_id: str, filename: str):
    try:
        payload = request.get_json(silent=True) or {}
        content = str(payload.get("content", ""))
        result = _get_adapter(proto).write_file(run_id, filename, content)
        return jsonify({"success": True, "file": result, "message": "文件已保存"})
    except KeyError:
        return jsonify({"success": False, "message": f"Protocol not implemented: {proto}"}), 501
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run file not found"}), 404
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
