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

from attack_resources.shared.ip_resource_catalog import list_protocol_resources, resolve_protocol_resource_path
from attack_resources.shared import credential_store
from attack_resources.shared.spiders import ShodanSpider, FOFASpider
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


from attack_resources.ntp.code.ntp_resource_scanner import NTPResourceScanner, PROBE_ACTIONS
from attack_resources.ntp.code.routes import (
    NTP_OUTPUT_ROOT,
    _bool as ntp_bool,
    _build_config_dict as ntp_build_config_dict,
    _float_or as ntp_float_or,
    _generate_run_id as ntp_generate_run_id,
    _int_or as ntp_int_or,
    _list_ip_files as ntp_list_ip_files,
    _list_run_dirs as ntp_list_run_dirs,
    _read_run_file as ntp_read_run_file,
    _read_run_log as ntp_read_run_log,
    ntp_registry,
    ScanConfig as NtpScanConfig,
)
from attack_resources.memcached.code.memcached_resource_scanner import (
    MEMCACHED_CMD_TYPES,
    MemcachedResourceScanner,
)
from attack_resources.memcached.code.routes import (
    MEMCACHED_OUTPUT_ROOT,
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
    ("prepare_zmap", "\u51c6\u5907 ZMap"),
    ("run_zmap_scan", "\u6267\u884c ZMap \u626b\u63cf"),
    ("process_scan_csv", "\u5904\u7406\u626b\u63cf CSV"),
    ("extract_ips", "\u63d0\u53d6 IP"),
    ("run_amplification_test", "\u6267\u884c\u653e\u5927\u6d4b\u8bd5"),
    ("analyze_amplification_log", "\u5206\u6790\u653e\u5927\u65e5\u5fd7"),
    ("extract_qualified_ips", "\u63d0\u53d6\u4f18\u8d28IP"),
]
DNS_STAGE_ORDER = [
    ("loading", "\u52a0\u8f7d IP \u5019\u9009"),
    ("scanning", "\u653e\u5927\u7387\u6d4b\u91cf"),
    ("filtering", "\u6309\u9608\u503c\u7b5b\u9009"),
    ("saving", "\u4fdd\u5b58\u7ed3\u679c"),
]

NTP_STAGE_ORDER = [
    ("loading", "\u52a0\u8f7d IP \u5019\u9009"),
    ("scanning", "\u6267\u884c NTP \u63a2\u6d4b"),
    ("filtering", "\u7b5b\u9009\u9ad8\u500d\u7387\u76ee\u6807"),
    ("saving", "\u4fdd\u5b58\u7ed3\u679c"),
]

MEMCACHED_STAGE_ORDER = [
    ("loading", "\u52a0\u8f7d IP \u5019\u9009"),
    ("scanning", "\u6267\u884c Memcached \u63a2\u6d4b"),
    ("filtering", "\u7b5b\u9009\u9ad8\u653e\u5927\u7387\u76ee\u6807"),
    ("saving", "\u4fdd\u5b58\u7ed3\u679c"),
]

ATTACK_RESOURCES_ROOT = Path(__file__).resolve().parents[1]


def _normalize_protocol_resource(proto: str, resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": resource["id"],
        "name": resource["display_name"],
        "filename": resource["filename"],
        "path": resource["path"],
        "full_path": resource["full_path"],
        "count": resource.get("count", resource.get("entry_count", 0)),
        "entry_count": resource.get("entry_count", 0),
        "protocols": resource.get("protocols", []),
        "source": resource.get("source"),
        "source_name": resource.get("source_name"),
        "type": resource.get("type"),
        "updated_at": resource.get("updated_at"),
        "location_label": resource.get("location_label"),
        "legacy": resource.get("legacy", False),
        "sub_dir": resource.get("sub_dir", ""),
        "bytes": resource.get("bytes", resource.get("size_bytes", 0)),
    }


def _list_protocol_resources(proto: str) -> list[dict[str, Any]]:
    return [_normalize_protocol_resource(proto, resource) for resource in list_protocol_resources(proto, ATTACK_RESOURCES_ROOT)]


def _resolve_protocol_resource(proto: str, value: str) -> Path | None:
    return resolve_protocol_resource_path(proto, value, ATTACK_RESOURCES_ROOT)



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
    qualified_ips = _tcp_get_qualified_ips(run_id)
    detail_items = [
        {"label": "\u5f53\u524d\u9636\u6bb5", "value": next((item["label"] for item in normalized_stages if item["key"] == current_stage), "-")},
        {"label": "\u5f00\u59cb\u65f6\u95f4", "value": summary.get("started_at") or "-"},
        {"label": "\u7ed3\u675f\u65f6\u95f4", "value": summary.get("ended_at") or "-"},
        {"label": "\u6a21\u62df\u8fd0\u884c", "value": "\u662f" if config.get("dry_run") else "\u5426"},
        {"label": "\u505c\u6b62\u8bf7\u6c42", "value": "\u5df2\u8bf7\u6c42" if summary.get("stop_requested") else "\u672a\u8bf7\u6c42"},
        {"label": "\u4f18\u8d28 IP", "value": len(qualified_ips)},
        {"label": "\u5931\u8d25\u539f\u56e0", "value": runtime_error or "-"},
    ]

    result_preview = {
        "type": "list",
        "title": "\u4f18\u8d28 IP",
        "items": qualified_ips[:5],
        "total": len(qualified_ips),
        "empty_text": "\u6682\u65e0\u4f18\u8d28 IP\u3002\u5b8c\u6574\u7ed3\u679c\u53ef\u901a\u8fc7\u8f93\u51fa\u6587\u4ef6\u67e5\u770b\u3002",
    } if qualified_ips else None

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
            "qualified_count": len(qualified_ips),
        },
        "detail_items": detail_items,
        "stages": normalized_stages,
        "artifacts": [_text_artifact_descriptor(file["name"], file.get("bytes", 0)) for file in files],
        "result_preview": result_preview,
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
                return {"success": False, "message": "\u9884\u68c0\u672a\u901a\u8fc7", "report": report}, 400

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
        "message": "TCP \u8d44\u6e90\u83b7\u53d6\u4efb\u52a1\u5df2\u521b\u5efa",
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
        "message": f"\u5df2\u6e05\u7406 {len(deleted)} \u6761\u5386\u53f2\u8bb0\u5f55",
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
        {"label": "\u5f53\u524d\u9636\u6bb5", "value": _dns_stage_status_label(stats.get("stage"), is_running)},
        {"label": "\u67e5\u8be2\u7c7b\u578b", "value": config_dict.get("query_type") or "-"},
        {"label": "DNSSEC", "value": "\u5f00\u542f" if config_dict.get("use_dnssec") is True else ("\u5173\u95ed" if config_dict.get("use_dnssec") is False else "-")},
        {"label": "\u5e76\u53d1\u6570", "value": config_dict.get("concurrency", "-")},
        {"label": "\u6700\u5c0f\u653e\u5927\u7387", "value": config_dict.get("min_amplification", "-")},
        {"label": "\u6700\u5c0f\u53ef\u9760\u6027", "value": config_dict.get("min_reliability", "-")},
        {"label": "\u4f18\u8d28 IP", "value": len(qualified_ips)},
        {"label": "\u5931\u8d25\u539f\u56e0", "value": runtime_error or "-"},
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
            "title": "\u4f18\u8d28 IP",
            "items": qualified_ips[:5],
            "total": len(qualified_ips),
            "empty_text": "\u6682\u65e0\u4f18\u8d28 IP\u3002\u5b8c\u6574\u7ed3\u679c\u53ef\u901a\u8fc7\u8f93\u51fa\u6587\u4ef6\u67e5\u770b\u3002",
        },
        "runtime_error": runtime_error,
    }


def _dns_stage_status_label(stage: str | None, is_running: bool) -> str:
    if stage == "done":
        return "\u5df2\u5b8c\u6210"
    if stage == "error":
        return "\u5931\u8d25"
    if stage == "stopped":
        return "\u5df2\u505c\u6b62"
    if stage == "saving":
        return "\u4fdd\u5b58\u4e2d" if is_running else "\u5df2\u4fdd\u5b58"
    if stage == "filtering":
        return "\u7b5b\u9009\u4e2d" if is_running else "\u5df2\u7b5b\u9009"
    if stage == "scanning":
        return "\u6d4b\u91cf\u4e2d" if is_running else "\u5df2\u6d4b\u91cf"
    if stage == "loading":
        return "\u52a0\u8f7d\u4e2d" if is_running else "\u5df2\u52a0\u8f7d"
    return "\u8fd0\u884c\u4e2d" if is_running else "\u7a7a\u95f2"


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
            "secondary_text": f"\u4f18\u8d28: {run.get('qualified_count', 0)} IPs",
            "badge_text": (run.get("stage") or run.get("status") or "-").upper(),
        })
    active_run_ids = dns_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _dns_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        available = _list_protocol_resources("dns")
        if not available:
            return {"success": False, "message": "\u6ca1\u6709\u53ef\u7528\u7684 IP \u5019\u9009\u6587\u4ef6"}, 400
        ip_file = available[0]["path"]
    resolved_ip_file = _resolve_protocol_resource("memcached", ip_file)
    if resolved_ip_file is None or not resolved_ip_file.exists():
        return {"success": False, "message": f"IP \u6587\u4ef6\u4e0d\u5b58\u5728: {ip_file}"}, 400

    domains_str = str(payload.get("test_domains", "")).strip()
    if domains_str:
        test_domains = [item.strip() for item in domains_str.replace(",", "\n").splitlines() if item.strip()]
    else:
        test_domains = DEFAULT_TEST_DOMAINS.copy()

    config = DnsScanConfig(
        ip_file=str(resolved_ip_file),
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
        return {"success": False, "message": f"\u4e0d\u652f\u6301\u7684\u67e5\u8be2\u7c7b\u578b: {config.query_type}"}, 400

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
        "message": "DNS \u8d44\u6e90\u83b7\u53d6\u4efb\u52a1\u5df2\u521b\u5efa",
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
        "message": f"\u5df2\u6e05\u7406 {len(deleted)} \u6761\u5386\u53f2\u8bb0\u5f55",
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
        return _list_protocol_resources("tcp")

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
            return {"success": cleaned, "message": "已清理任务产物" if cleaned else "\u672a\u627e\u5230\u6b63\u5728\u8fd0\u884c\u7684\u8fdb\u7a0b"}
        return {"success": stopped, "message": "\u6b63\u5728\u505c\u6b62 TCP \u626b\u63cf" if stopped else "\u672a\u627e\u5230\u6b63\u5728\u8fd0\u884c\u7684\u8fdb\u7a0b"}

    def get_results(self, run_id: str) -> dict[str, Any]:
        run = _build_tcp_run_payload(run_id)
        qualified = _tcp_get_qualified_ips(run_id)
        return {
            "success": True,
            "result_preview": run.get("result_preview"),
            "artifacts": run.get("artifacts", []),
            "qualified_ips": qualified,
            "qualified_count": len(qualified),
        }

    def read_file(self, run_id: str, filename: str) -> dict[str, Any]:
        return tcp_read_run_file(run_id, filename, TCP_OUTPUT_ROOT)

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        return tcp_write_run_file(run_id, filename, content, TCP_OUTPUT_ROOT)


class DnsAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("dns")

    def list_resources(self) -> list[dict[str, Any]]:
        return _list_protocol_resources("dns")

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
        {"label": "\u5f53\u524d\u9636\u6bb5", "value": _memcached_stage_status_label(stats.get("stage"), is_running)},
        {"label": "\u547d\u4ee4\u7c7b\u578b", "value": config_dict.get("cmd_type") or "-"},
        {"label": "\u6570\u636e\u5927\u5c0f(KB)", "value": config_dict.get("data_size_kb", "-")},
        {"label": "\u5e76\u53d1\u6570", "value": config_dict.get("concurrency", "-")},
        {"label": "\u6700\u5c0f\u653e\u5927\u7387", "value": config_dict.get("min_amplification", "-")},
        {"label": "\u6700\u5c0f\u53ef\u9760\u6027", "value": config_dict.get("min_reliability", "-")},
        {"label": "\u4f18\u8d28 IP", "value": len(qualified_ips)},
        {"label": "\u5931\u8d25\u539f\u56e0", "value": runtime_error or "-"},
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
            "title": "\u4f18\u8d28 IP",
            "items": qualified_ips[:5],
            "total": len(qualified_ips),
            "empty_text": "\u6682\u65e0\u4f18\u8d28 IP\u3002\u5b8c\u6574\u7ed3\u679c\u53ef\u901a\u8fc7\u8f93\u51fa\u6587\u4ef6\u67e5\u770b\u3002",
        },
        "runtime_error": runtime_error,
    }


def _memcached_stage_status_label(stage: str | None, is_running: bool) -> str:
    if stage == "done":
        return "\u5df2\u5b8c\u6210"
    if stage == "error":
        return "\u5931\u8d25"
    if stage == "stopped":
        return "\u5df2\u505c\u6b62"
    if stage == "saving":
        return "\u4fdd\u5b58\u4e2d" if is_running else "\u5df2\u4fdd\u5b58"
    if stage == "filtering":
        return "\u7b5b\u9009\u4e2d" if is_running else "\u5df2\u7b5b\u9009"
    if stage == "scanning":
        return "\u63a2\u6d4b\u4e2d" if is_running else "\u5df2\u63a2\u6d4b"
    if stage == "loading":
        return "\u52a0\u8f7d\u4e2d" if is_running else "\u5df2\u52a0\u8f7d"
    return "\u8fd0\u884c\u4e2d" if is_running else "\u7a7a\u95f2"


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
            "secondary_text": f"\u4f18\u8d28: {run.get('qualified_count', 0)} IPs",
            "badge_text": (run.get("stage") or run.get("status") or "-").upper(),
        })
    active_run_ids = memcached_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _memcached_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        available = _list_protocol_resources("memcached")
        if not available:
            return {"success": False, "message": "\u6ca1\u6709\u53ef\u7528\u7684 IP \u5019\u9009\u6587\u4ef6"}, 400
        ip_file = available[0]["path"]
    resolved_ip_file = _resolve_protocol_resource("memcached", ip_file)
    if resolved_ip_file is None or not resolved_ip_file.exists():
        return {"success": False, "message": f"IP \u6587\u4ef6\u4e0d\u5b58\u5728: {ip_file}"}, 400

    config = MemcachedScanConfig(
        ip_file=str(resolved_ip_file),
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
        return {"success": False, "message": f"\u4e0d\u652f\u6301\u7684\u547d\u4ee4\u7c7b\u578b: {config.cmd_type}"}, 400

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
        except Exception as exc:
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
        "message": "Memcached \u8d44\u6e90\u626b\u63cf\u5df2\u542f\u52a8",
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
        "message": f"\u5df2\u6e05\u7406 {len(deleted)} \u6761\u5386\u53f2\u8bb0\u5f55",
        "deleted": deleted,
        "skipped": skipped,
    }


class MemcachedAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("memcached")

    def list_resources(self) -> list[dict[str, Any]]:
        return _list_protocol_resources("memcached")

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
            return {"success": True, "message": "\u6b63\u5728\u505c\u6b62 Memcached \u8d44\u6e90\u626b\u63cf..."}
        return {"success": False, "message": "\u6ca1\u6709\u6b63\u5728\u8fd0\u884c\u7684\u626b\u63cf\u4efb\u52a1"}

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


def _build_ntp_run_payload(run_id: str) -> dict[str, Any]:
    scanner = ntp_registry.get_scanner(run_id)
    run_dir = NTP_OUTPUT_ROOT / run_id
    stats: dict[str, Any] = {}
    if scanner:
        stats = scanner.get_stats()
        is_running = ntp_registry.is_running(run_id)
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

    runtime_error = ntp_registry.get_error(run_id) or str(stats.get("error") or "")
    config = ntp_registry.get_config(run_id)
    if config:
        config_dict = ntp_build_config_dict(config)
    else:
        config_dict = stats.get("config") if isinstance(stats.get("config"), dict) else None
    config_dict = config_dict or {}

    current_stage = stats.get("current_stage") or stats.get("stage")
    normalized_stages = []
    stage_states = stats.get("stages", {})
    final_stage = stats.get("stage")
    for stage_key, stage_label in NTP_STAGE_ORDER:
        stage_status = stage_states.get(stage_key, {}).get("status")
        if not stage_status and is_running and current_stage == stage_key:
            stage_status = "running"
        if not stage_status and final_stage == "done":
            stage_status = "completed"
        normalized_stages.append({
            "key": stage_key,
            "label": stage_label,
            "status": _normalize_ntp_stage_status(stage_status, final_stage, current_stage, stage_key),
        })

    artifacts = []
    if run_dir.exists():
        for file in sorted(run_dir.iterdir()):
            if file.is_file():
                artifacts.append(_text_artifact_descriptor(file.name, file.stat().st_size, editable=False))

    qualified_ips = _ntp_get_qualified_ips(run_id, scanner)
    detail_items = [
        {"label": "当前阶段", "value": _ntp_stage_status_label(stats.get("stage"), is_running)},
        {"label": "探测动作", "value": config_dict.get("probe_action") or "-"},
        {"label": "并发数", "value": config_dict.get("concurrency", "-")},
        {"label": "最小放大率", "value": config_dict.get("min_amplification", "-")},
        {"label": "最小可用性", "value": config_dict.get("min_availability", "-")},
        {"label": "优质 IP", "value": len(qualified_ips)},
        {"label": "失败原因", "value": runtime_error or "-"},
    ]

    return {
        "run_id": run_id,
        "proto": "ntp",
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


def _ntp_stage_status_label(stage: str | None, is_running: bool) -> str:
    if stage == "done":
        return "\u5df2\u5b8c\u6210"
    if stage == "error":
        return "\u5931\u8d25"
    if stage == "stopped":
        return "\u5df2\u505c\u6b62"
    if stage == "saving":
        return "\u4fdd\u5b58\u4e2d" if is_running else "\u5df2\u4fdd\u5b58"
    if stage == "filtering":
        return "\u7b5b\u9009\u4e2d" if is_running else "\u5df2\u7b5b\u9009"
    if stage == "scanning":
        return "\u63a2\u6d4b\u4e2d" if is_running else "\u5df2\u63a2\u6d4b"
    if stage == "loading":
        return "\u52a0\u8f7d\u4e2d" if is_running else "\u5df2\u52a0\u8f7d"
    return "\u8fd0\u884c\u4e2d" if is_running else "\u7a7a\u95f2"


def _normalize_ntp_stage_status(stage_status: str | None, final_stage: str | None, current_stage: str | None, stage_key: str) -> str:
    if stage_status in {"completed", "failed", "stopped", "running"}:
        return stage_status
    if final_stage == "done":
        return "completed"
    if final_stage == "error" and current_stage == stage_key:
        return "failed"
    if final_stage == "stopped" and current_stage == stage_key:
        return "stopped"
    return "pending"


def _ntp_get_qualified_ips(run_id: str, scanner: NTPResourceScanner | None) -> list[str]:
    if scanner:
        return scanner.get_qualified_ips()
    ip_file = NTP_OUTPUT_ROOT / run_id / "qualified_ips.txt"
    if not ip_file.exists():
        return []
    return [
        line.strip()
        for line in ip_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _build_ntp_runs_list() -> dict[str, Any]:
    runs = []
    for run in ntp_list_run_dirs():
        run_id = run["run_id"]
        runs.append({
            "run_id": run_id,
            "proto": "ntp",
            "status": run.get("status", "idle"),
            "is_running": ntp_registry.is_running(run_id),
            "primary_text": run_id,
            "secondary_text": f"优质: {run.get('qualified_count', 0)} IPs",
            "badge_text": (run.get("stage") or run.get("status") or "-").upper(),
        })
    active_run_ids = ntp_registry.active_run_ids()
    return {"runs": runs, "active_run_ids": active_run_ids, "running_count": len(active_run_ids)}


def _ntp_start(payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ip_file = str(payload.get("ip_file") or "")
    if not ip_file:
        available = _list_protocol_resources("ntp")
        if not available:
            return {"success": False, "message": "没有可用的 IP 候选文件"}, 400
        ip_file = available[0]["path"]
    if not Path(ip_file).exists():
        return {"success": False, "message": f"IP 文件不存在: {ip_file}"}, 400

    probe_action = str(payload.get("probe_action", "both")).strip().lower()
    if probe_action not in PROBE_ACTIONS:
        probe_action = "both"

    config = NtpScanConfig(
        ip_file=str(resolved_ip_file),
        output_dir=str(NTP_OUTPUT_ROOT / ntp_generate_run_id()),
        probe_action=probe_action,
        timeout_sec=ntp_float_or(payload.get("timeout_sec"), 3.0),
        concurrency=ntp_int_or(payload.get("concurrency"), 50),
        min_amplification=ntp_float_or(payload.get("min_amplification"), 50.0),
        min_availability=ntp_float_or(payload.get("min_availability"), 30.0),
        max_ips=ntp_int_or(payload.get("max_ips"), 0),
    )

    run_id = Path(config.output_dir).name
    os.makedirs(config.output_dir, exist_ok=True)
    log_path = Path(config.output_dir) / "pipeline.log"
    config_dict = ntp_build_config_dict(config)
    scanner = NTPResourceScanner()

    def log_persister(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    def scan_worker() -> None:
        try:
            scanner.run_scan(config, log_callback=log_persister)
        except Exception as exc:  # pragma: no cover - defensive thread path
            ntp_registry.set_error(run_id, f"{exc}\n{traceback.format_exc()}")
        finally:
            stats_file = Path(config.output_dir) / "final_stats.json"
            try:
                final_stats = scanner.get_stats()
                final_stats.setdefault("config", config_dict)
                stats_file.write_text(json.dumps(final_stats, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    thread = Thread(target=scan_worker, daemon=True)
    ntp_registry.register(run_id, scanner, thread, config)
    thread.start()
    return {
        "success": True,
        "message": "NTP 资源获取任务已创建",
        "run_ids": [run_id],
        "runs": [{"run_id": run_id}],
    }, 200


def _ntp_clear() -> dict[str, Any]:
    active = set(ntp_registry.active_run_ids())
    deleted: list[str] = []
    skipped: list[str] = []
    if NTP_OUTPUT_ROOT.exists():
        for directory in sorted(NTP_OUTPUT_ROOT.iterdir()):
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
    ntp_registry.forget(deleted)
    return {
        "success": True,
        "message": f"已清除 {len(deleted)} 条历史记录",
        "deleted": deleted,
        "skipped": skipped,
    }



class NtpAdapter(_ProtoAdapter):
    def __init__(self) -> None:
        super().__init__("ntp")

    def list_resources(self) -> list[dict[str, Any]]:
        return _list_protocol_resources("ntp")

    def list_runs(self) -> dict[str, Any]:
        return _build_ntp_runs_list()

    def start_run(self, payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
        return _ntp_start(payload)

    def clear_runs(self) -> dict[str, Any]:
        return _ntp_clear()

    def get_run(self, run_id: str) -> dict[str, Any]:
        return _build_ntp_run_payload(run_id)

    def get_logs(self, run_id: str, tail: int) -> str:
        return ntp_read_run_log(run_id, tail)

    def stop_run(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        scanner = ntp_registry.get_scanner(run_id)
        if scanner and scanner.is_running:
            scanner.stop()
            return {"success": True, "message": "正在停止 NTP 资源扫描…"}
        return {"success": False, "message": "没有正在运行的扫描"}

    def get_results(self, run_id: str) -> dict[str, Any]:
        scanner = ntp_registry.get_scanner(run_id)
        qualified = _ntp_get_qualified_ips(run_id, scanner)
        if scanner:
            results = scanner.get_results(limit=500)
        else:
            csv_file = NTP_OUTPUT_ROOT / run_id / "scan_results.csv"
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
            "path": str(NTP_OUTPUT_ROOT / run_id / filename),
            "type": "text",
            "editable": False,
            "content": ntp_read_run_file(run_id, filename),
        }

    def write_file(self, run_id: str, filename: str, content: str) -> dict[str, Any]:
        raise ValueError("File type is not editable")


ADAPTERS: dict[str, _ProtoAdapter] = {
    "tcp": TcpAdapter(),
    "dns": DnsAdapter(),
    "ntp": NtpAdapter(),
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


from attack_resources.shared.ip_resource_manager import resource_manager


@attack_resource_bp.route("/resources", methods=["GET"])
def ip_resources_list():
    try:
        filter_type = request.args.get("type")
        filter_source = request.args.get("source")
        filter_country = request.args.get("country")
        filter_protocol = request.args.get("protocol")
        result = resource_manager.list_resources(
            filter_type=filter_type,
            filter_source=filter_source,
            filter_country=filter_country,
            filter_protocol=filter_protocol,
        )
        return jsonify({"success": True, **result})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/<path:path>", methods=["GET"])
def ip_resource_read(path: str):
    try:
        result = resource_manager.read_resource(path)
        return jsonify({"success": True, "resource": result})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "资源文件不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/<path:path>", methods=["PUT"])
def ip_resource_write(path: str):
    try:
        payload = request.get_json(silent=True) or {}
        content = str(payload.get("content", ""))
        result = resource_manager.write_resource(path, content)
        return jsonify({"success": True, "resource": result, "message": "文件已更新"})
    except FileNotFoundError:
        return jsonify({"success": False, "message": "资源文件不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources", methods=["POST"])
def ip_resource_create():
    try:
        payload = request.get_json(silent=True) or {}
        filename = str(payload.get("filename", ""))
        content = str(payload.get("content", ""))
        metadata = payload.get("metadata", {})
        if not filename:
            return jsonify({"success": False, "message": "文件名不能为空"}), 400
        result = resource_manager.create_resource(filename, content, metadata)
        return jsonify({"success": True, "resource": result, "message": "文件已创建"}), 201
    except FileExistsError:
        return jsonify({"success": False, "message": "文件已存在"}), 409
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/<path:path>", methods=["DELETE"])
def ip_resource_delete(path: str):
    try:
        deleted = resource_manager.delete_resource(path)
        if deleted:
            return jsonify({"success": True, "message": "文件已删除"})
        else:
            return jsonify({"success": False, "message": "资源文件不存在"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/fetch", methods=["POST"])
def ip_resource_fetch():
    try:
        payload = request.get_json(silent=True) or {}
        spider_name = str(payload.get("spider", ""))
        params = payload.get("params", {})
        if not spider_name:
            return jsonify({"success": False, "message": "爬虫名称不能为空"}), 400
        result = resource_manager.fetch_auto_resources(spider_name, params)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/merge", methods=["POST"])
def ip_resource_merge():
    try:
        payload = request.get_json(silent=True) or {}
        sources = payload.get("sources", [])
        output_name = str(payload.get("output_name", ""))
        if not sources or not output_name:
            return jsonify({"success": False, "message": "源文件列表和输出文件名不能为空"}), 400
        result = resource_manager.merge_resources(sources, output_name)
        return jsonify({"success": True, **result, "message": "合并完成"}), 201
    except FileExistsError:
        return jsonify({"success": False, "message": "输出文件已存在"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/sources", methods=["GET"])
def ip_resource_sources():
    try:
        sources = resource_manager.get_source_info()
        return jsonify({"success": True, "sources": sources})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/resources/countries", methods=["GET"])
def ip_resource_countries():
    try:
        countries = resource_manager.get_country_list()
        return jsonify({"success": True, "countries": countries})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ====================== 凭据管理 API ======================
_VALID_CRED_SOURCES = {"shodan", "fofa"}


def _is_shodan_configured(creds):
    return bool(creds and creds.get("api_key"))


def _is_fofa_configured(creds):
    return bool(creds and creds.get("email") and creds.get("key"))


def _is_cookies_configured(creds):
    cookies = (creds or {}).get("cookies")
    return bool(cookies and isinstance(cookies, dict) and cookies)


def _credential_status(source, creds):
    if source == "shodan":
        api_key_configured = _is_shodan_configured(creds)
    else:
        api_key_configured = _is_fofa_configured(creds)
    cookies_configured = _is_cookies_configured(creds)
    return {
        "configured": api_key_configured or cookies_configured,
        "api_key_configured": api_key_configured,
        "cookies_configured": cookies_configured,
        "updated_at": (creds or {}).get("updated_at"),
    }


def _validate_cred_payload(source, payload):
    """返回 (ok, error_message)。"""
    if source == "shodan":
        if not payload.get("api_key"):
            return False, "缺少必填字段: api_key"
    else:  # fofa
        if not payload.get("email"):
            return False, "缺少必填字段: email"
        if not payload.get("key"):
            return False, "缺少必填字段: key"
    return True, None


@attack_resource_bp.route("/credentials", methods=["GET"])
def credentials_status():
    try:
        all_creds = credential_store.load_credentials()
        result = {}
        for source in _VALID_CRED_SOURCES:
            result[source] = _credential_status(source, all_creds.get(source))
        return jsonify({"success": True, "credentials": result})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>", methods=["POST"])
def save_credentials_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        payload = request.get_json(silent=True) or {}
        ok, message = _validate_cred_payload(source, payload)
        if not ok:
            return jsonify({"success": False, "message": message}), 400

        credential_store.save_credentials(source, payload)

        # 保存后立即测试（spider 会从 store 重新读取最新凭据）
        if source == "shodan":
            check_result = ShodanSpider().check_api_key()
        else:
            check_result = FOFASpider().check_credentials()

        response = {
            "success": True,
            "valid": bool(check_result.get("valid")),
            "user": check_result.get("user"),
            "error": check_result.get("error"),
        }
        # 透传 Shodan credits/plan/warning 字段
        for k in ("query_credits", "scan_credits", "plan", "warning"):
            if k in check_result:
                response[k] = check_result[k]
        return jsonify(response)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>", methods=["DELETE"])
def clear_credentials_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        credential_store.clear_credentials(source)
        display_name = source.capitalize() if source == "shodan" else "FOFA"
        return jsonify({"success": True, "message": f"{display_name} 凭据已清除"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>/test", methods=["POST"])
def test_credentials_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        payload = request.get_json(silent=True) or {}
        ok, message = _validate_cred_payload(source, payload)
        if not ok:
            return jsonify({"success": False, "message": message}), 400

        # 仅用请求体中的凭据测试，不写入文件
        if source == "shodan":
            check_result = ShodanSpider().check_api_key(credentials=payload)
        else:
            check_result = FOFASpider().check_credentials(credentials=payload)

        response = {
            "success": True,
            "valid": bool(check_result.get("valid")),
            "user": check_result.get("user"),
            "error": check_result.get("error"),
        }
        # 透传 Shodan credits/plan/warning 字段
        for k in ("query_credits", "scan_credits", "plan", "warning"):
            if k in check_result:
                response[k] = check_result[k]
        return jsonify(response)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ---------- Cookie 管理（方式二/三） ----------

_COOKIE_DOMAINS = {
    "shodan": ".shodan.io",
    "fofa": ".fofa.info",
}

_REQUIRED_COOKIE_FIELDS = {
    "shodan": "shodan_session",
    "fofa": "FOFA_TOKEN",
}


def _parse_cookie_string(cookie_string: str) -> dict:
    """将 'key1=val1; key2=val2' 解析为 dict。"""
    cookies = {}
    for pair in cookie_string.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        key, _, val = pair.partition("=")
        key = key.strip()
        if key:
            cookies[key] = val.strip()
    return cookies


@attack_resource_bp.route("/credentials/<source>/cookies", methods=["GET"])
def get_cookies_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400
        cookies = credential_store.get_cookies(source)
        creds = credential_store.get_credentials(source) or {}
        return jsonify({
            "success": True,
            "configured": bool(cookies),
            "updated_at": creds.get("updated_at"),
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>/cookies", methods=["POST"])
def save_cookies_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        payload = request.get_json(silent=True) or {}
        cookie_string = (payload.get("cookie_string") or "").strip()
        if not cookie_string:
            return jsonify({"success": False, "message": "缺少 cookie_string 字段"}), 400

        cookies_dict = _parse_cookie_string(cookie_string)
        if not cookies_dict:
            return jsonify({"success": False, "message": "cookie 字符串解析失败，请检查格式（应为 key1=val1; key2=val2）"}), 400

        credential_store.save_cookies(source, cookies_dict)
        display_name = source.capitalize() if source == "shodan" else "FOFA"

        # 关键字段校验
        required_field = _REQUIRED_COOKIE_FIELDS.get(source)
        warning = None
        if required_field and required_field not in cookies_dict:
            if source == "shodan":
                warning = f"Cookie 已保存，但未检测到 {required_field} 字段。Shodan 登录态依赖该字段，仅提供 polito 等偏好 cookie 无法通过登录态校验。请重新从浏览器 DevTools 复制完整 Cookie 字符串。"
            else:
                warning = f"Cookie 已保存，但未检测到 {required_field} 字段。FOFA 登录态依赖该字段，请重新从浏览器 DevTools 复制完整 Cookie 字符串。"

        response = {"success": True, "message": f"{display_name} Cookie 已保存（{len(cookies_dict)} 项）"}
        if warning:
            response["warning"] = warning
        return jsonify(response)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>/cookies/auto", methods=["POST"])
def auto_extract_cookies_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        # 提前导入 browser_cookie3，若未安装则给出明确提示
        try:
            import browser_cookie3
        except ImportError:
            return jsonify({
                "success": False,
                "message": "未安装 browser_cookie3 模块，请在服务器上运行: pip install browser_cookie3==0.16.2",
                "missing_module": True,
            }), 200

        domain = _COOKIE_DOMAINS[source]
        cookies_dict = None

        for browser_name, load_fn_name in [
            ("chrome", "chrome"),
            ("firefox", "firefox"),
            ("edge", "edge"),
        ]:
            try:
                load_fn = getattr(browser_cookie3, load_fn_name, None)
                if load_fn is None:
                    continue
                cj = load_fn(domain_name=domain)
                cookies_dict = {c.name: c.value for c in cj if domain in (c.domain or "")}
                if cookies_dict:
                    break
            except Exception:
                continue

        if not cookies_dict:
            return jsonify({
                "success": False,
                "message": f"未能从浏览器自动获取 {source} cookie。请确保已在浏览器中登录 {domain}。",
            })

        credential_store.save_cookies(source, cookies_dict)
        return jsonify({"success": True, "count": len(cookies_dict)})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>/cookies/test", methods=["POST"])
def test_cookies_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        if source == "shodan":
            check_result = ShodanSpider().check_web_cookies()
        else:
            check_result = FOFASpider().check_web_cookies()

        return jsonify({
            "success": True,
            "valid": bool(check_result.get("valid")),
            "ip_count": check_result.get("ip_count", 0),
            "error": check_result.get("error"),
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@attack_resource_bp.route("/credentials/<source>/cookies", methods=["DELETE"])
def clear_cookies_route(source: str):
    try:
        if source not in _VALID_CRED_SOURCES:
            return jsonify({"success": False, "message": f"未知的数据源: {source}"}), 400

        credential_store.clear_cookies(source)
        display_name = source.capitalize() if source == "shodan" else "FOFA"
        return jsonify({"success": True, "message": f"{display_name} Cookie 已清除"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


def _tcp_get_qualified_ips(run_id: str) -> list[str]:
    ip_file = TCP_OUTPUT_ROOT / run_id / "qualified_ips.txt"
    if not ip_file.exists():
        return []
    return [
        line.strip()
        for line in ip_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


@attack_resource_bp.route("/tcp/runs/<run_id>/qualified-ips", methods=["GET"])
def tcp_qualified_ips(run_id: str):
    try:
        qualified = _tcp_get_qualified_ips(run_id)
        return jsonify({
            "success": True,
            "qualified_ips": qualified,
            "qualified_count": len(qualified),
        })
    except FileNotFoundError:
        return jsonify({"success": False, "message": "Run not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
