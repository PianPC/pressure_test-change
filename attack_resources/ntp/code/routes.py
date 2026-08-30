"""NTP 攻击资源获取 - Flask Blueprint

路由前缀: /api/ntp-scan/
提供 NTP 放大率测量扫描的完整 API：
  - IP 资源文件管理
  - 扫描任务创建/停止/查询
  - 日志与产物读取

通用流程（运行注册表、run 目录读写、任务启停等）由
``attack_resources.shared.protocol_scan_routes`` 提供，本模块只保留
NTP 特有的配置解析、校验与元数据端点。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify

from attack_resources.shared.protocol_scan_routes import (
    ProtocolScanSpec,
    _bool,
    _float_or,
    _int_or,
    create_scan_blueprint,
    _generate_run_id as _generate_run_id_shared,
    _list_ip_files as _list_ip_files_shared,
    _list_run_dirs as _list_run_dirs_shared,
    _normalize_resource,
    _read_run_file as _read_run_file_shared,
    _read_run_log as _read_run_log_shared,
    _resolve_ip_file as _resolve_ip_file_shared,
)

from attack_resources.ntp.code.ntp_resource_scanner import (
    NTPResourceScanner,
    ScanConfig,
    PROBE_ACTIONS,
)

# 路径常量
REPO_ROOT = Path(__file__).resolve().parents[3]  # pressure_test-change/
NTP_OUTPUT_ROOT = REPO_ROOT / "attack_resources" / "ntp" / "runs" / "ntp_scan"
NTP_RESOURCES_ROOT = REPO_ROOT / "attack_resources" / "ntp" / "resources"
SHARED_IP_LISTS = REPO_ROOT / "attack_resources" / "shared" / "ip_lists"
ATTACK_RESOURCES_ROOT = REPO_ROOT / "attack_resources"

# 默认候选 IP 文件查找路径
DEFAULT_IP_SEARCH_DIRS = [
    SHARED_IP_LISTS,
    NTP_RESOURCES_ROOT / "ip_lists",
]


def _build_config_dict(config: ScanConfig) -> Dict[str, Any]:
    return {
        "ip_file": Path(config.ip_file).name,
        "probe_action": config.probe_action,
        "timeout_sec": config.timeout_sec,
        "concurrency": config.concurrency,
        "min_amplification": config.min_amplification,
        "min_availability": config.min_availability,
        "max_ips": config.max_ips,
        "ntp_port": config.ntp_port,
    }


def _build_config(
    resolved_ip_file: Path, output_dir: str, payload: Dict[str, Any]
) -> Tuple[ScanConfig, Optional[Tuple[str, int]]]:
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
    return config, None


def _register_extra_routes(bp: Blueprint) -> None:
    @bp.route("/probe-actions", methods=["GET"])
    def probe_actions():
        """返回支持的探测动作"""
        return jsonify({
            "success": True,
            "actions": {key: val for key, val in PROBE_ACTIONS.items()},
        })


_spec = ProtocolScanSpec(
    protocol="ntp",
    display_name="NTP",
    blueprint_name="ntp_scan",
    url_prefix="/api/ntp-scan",
    run_id_prefix="ntp",
    output_root_getter=lambda: NTP_OUTPUT_ROOT,
    attack_resources_root=ATTACK_RESOURCES_ROOT,
    scanner_factory=NTPResourceScanner,
    build_config=_build_config,
    config_to_dict=_build_config_dict,
)

ntp_scan_bp, ntp_registry = create_scan_blueprint(_spec, _register_extra_routes)


# ── 兼容 re-export（attack_resource_api.py 依赖这些符号） ──


def _list_ip_files(search_dirs: Optional[list] = None):
    del search_dirs
    return _list_ip_files_shared("ntp", ATTACK_RESOURCES_ROOT)


def _resolve_ip_file(value: str):
    return _resolve_ip_file_shared("ntp", ATTACK_RESOURCES_ROOT, value)


def _generate_run_id() -> str:
    return _generate_run_id_shared("ntp")


def _list_run_dirs():
    return _list_run_dirs_shared(NTP_OUTPUT_ROOT, ntp_registry)


def _read_run_file(run_id: str, filename: str) -> str:
    return _read_run_file_shared(NTP_OUTPUT_ROOT, run_id, filename)


def _read_run_log(run_id: str, tail: int = 200) -> str:
    return _read_run_log_shared(NTP_OUTPUT_ROOT, ntp_registry, run_id, tail)
