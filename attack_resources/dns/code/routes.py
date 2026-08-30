"""DNS 攻击资源获取 - Flask Blueprint

路由前缀: /api/dns-scan/
提供 DNS 放大率测量扫描的完整 API：
  - IP 资源文件管理
  - 扫描任务创建/停止/查询
  - 日志与产物读取

通用流程（运行注册表、run 目录读写、任务启停等）由
``attack_resources.shared.protocol_scan_routes`` 提供，本模块只保留
DNS 特有的配置解析、校验与元数据端点。
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

from attack_resources.dns.code.dns_resource_scanner import (
    DNSResourceScanner,
    ScanConfig,
    DNS_TYPE_MAP,
    DEFAULT_TEST_DOMAINS,
)

# 路径常量
REPO_ROOT = Path(__file__).resolve().parents[3]  # pressure_test-change/
DNS_OUTPUT_ROOT = REPO_ROOT / "attack_resources" / "dns" / "runs" / "dns_scan"
DNS_RESOURCES_ROOT = REPO_ROOT / "attack_resources" / "dns" / "resources"
SHARED_IP_LISTS = REPO_ROOT / "attack_resources" / "shared" / "ip_lists"
ATTACK_RESOURCES_ROOT = REPO_ROOT / "attack_resources"

# 默认候选 IP 文件查找路径
DEFAULT_IP_SEARCH_DIRS = [
    SHARED_IP_LISTS,
    DNS_RESOURCES_ROOT,
]


def _build_config_dict(config: ScanConfig) -> Dict[str, Any]:
    return {
        "ip_file": Path(config.ip_file).name,
        "query_type": config.query_type,
        "use_dnssec": config.use_dnssec,
        "timeout_sec": config.timeout_sec,
        "concurrency": config.concurrency,
        "min_amplification": config.min_amplification,
        "min_reliability": config.min_reliability,
        "max_ips": config.max_ips,
        "test_domains": list(config.test_domains),
    }


def _build_config(
    resolved_ip_file: Path, output_dir: str, payload: Dict[str, Any]
) -> Tuple[ScanConfig, Optional[Tuple[str, int]]]:
    # 解析域名
    domains_str = str(payload.get("test_domains", "")).strip()
    if domains_str:
        test_domains = [
            d.strip()
            for d in domains_str.replace(",", "\n").splitlines()
            if d.strip()
        ]
    else:
        test_domains = DEFAULT_TEST_DOMAINS.copy()

    config = ScanConfig(
        ip_file=str(resolved_ip_file),
        output_dir=output_dir,
        test_domains=test_domains,
        query_type=str(payload.get("query_type", "TXT")).upper(),
        use_dnssec=_bool(payload.get("use_dnssec", True)),
        timeout_sec=_float_or(payload.get("timeout_sec"), 3.0),
        concurrency=_int_or(payload.get("concurrency"), 80),
        min_amplification=_float_or(payload.get("min_amplification"), 3.0),
        min_reliability=_float_or(payload.get("min_reliability"), 50.0),
        max_ips=_int_or(payload.get("max_ips"), 0),
    )

    # 校验
    if config.query_type not in DNS_TYPE_MAP:
        return config, (f"不支持的查询类型: {config.query_type}", 400)
    return config, None


def _register_extra_routes(bp: Blueprint) -> None:
    @bp.route("/query-types", methods=["GET"])
    def query_types():
        """返回支持的 DNS 查询类型"""
        return jsonify({
            "success": True,
            "types": {name: val for name, val in DNS_TYPE_MAP.items()},
        })


_spec = ProtocolScanSpec(
    protocol="dns",
    display_name="DNS",
    blueprint_name="dns_scan",
    url_prefix="/api/dns-scan",
    run_id_prefix="dns",
    output_root_getter=lambda: DNS_OUTPUT_ROOT,
    attack_resources_root=ATTACK_RESOURCES_ROOT,
    scanner_factory=DNSResourceScanner,
    build_config=_build_config,
    config_to_dict=_build_config_dict,
)

dns_scan_bp, dns_registry = create_scan_blueprint(_spec, _register_extra_routes)


# ── 兼容 re-export（attack_resource_api.py 依赖这些符号） ──


def _list_ip_files(search_dirs: Optional[list] = None):
    del search_dirs
    return _list_ip_files_shared("dns", ATTACK_RESOURCES_ROOT)


def _resolve_ip_file(value: str):
    return _resolve_ip_file_shared("dns", ATTACK_RESOURCES_ROOT, value)


def _generate_run_id() -> str:
    return _generate_run_id_shared("dns")


def _list_run_dirs():
    return _list_run_dirs_shared(DNS_OUTPUT_ROOT, dns_registry)


def _read_run_file(run_id: str, filename: str) -> str:
    return _read_run_file_shared(DNS_OUTPUT_ROOT, run_id, filename)


def _read_run_log(run_id: str, tail: int = 200) -> str:
    return _read_run_log_shared(DNS_OUTPUT_ROOT, dns_registry, run_id, tail)
