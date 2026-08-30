"""协议 IP 列表文件读取与元信息管理。

拆分前位于 ``app.py`` 第 392-526 行。为避免与 ``attack_resources.shared``
产生循环导入，这里保留对其公共函数的调用，同时维持所有路由 helper 的签名
与返回结构完全一致。
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants as _c

# 注意：
# 常量都通过 ``_c.XXX`` 访问，以便在 unittest.mock.patch.object(app, "ATTACK_RESOURCES_ROOT")
# 时通过同步到 pressure.constants 上的新值生效。不要使用 ``from .constants import X``
# 的直接名字绑定方式，否则 patch 无法穿透。

# 延迟从 attack_resources.shared 导入，避免启动期循环依赖
from attack_resources.shared.ip_resource_catalog import (
    count_ip_entries,
    list_protocol_local_resources,
    resolve_protocol_local_resource_path,
)

logger = logging.getLogger(__name__)


def _build_geo_points(method: str, entries: List[str]) -> Dict[str, Any]:
    # 延迟导入以规避 servers.py <-> geoip_utils.py 的循环依赖
    from .geoip_utils import build_geo_points

    return build_geo_points(method, entries=entries)


def is_valid_server_method(method: str) -> bool:
    return method in _c.VALID_SERVER_PROTOCOLS


def get_server_file(method: str) -> str:
    return os.path.join(
        _c.ATTACK_RESOURCES_ROOT, method, "resources", "ip_lists", "default.txt"
    )


def get_default_server_file_content(method: str) -> str:
    # 保持与 app.py 完全一致的占位内容；乱码注释对应 UTF-8 文案
    return "# ???????????IP?????n"


def _list_server_file_sources(method: str) -> List[Dict[str, Any]]:
    """返回协议 IP 列表文件的元信息（供文件管理路由使用）。"""
    resources = list_protocol_local_resources(method, _c.ATTACK_RESOURCES_ROOT)
    return [
        {
            "id": item["id"],
            "name": item["filename"],
            "display_name": item["display_name"],
            "path": item["path"],
            "full_path": item["full_path"],
            "entry_count": item["entry_count"],
            "editable": True,
            "location_label": item.get("location_label"),
            "protocols": item.get("protocols", []),
            "source": item.get("source"),
            "source_name": item.get("source_name"),
            "type": item.get("type"),
            "updated_at": item.get("updated_at"),
            "legacy": item.get("legacy", False),
            "sub_dir": item.get("sub_dir", ""),
        }
        for item in resources
    ]


def list_server_sources(method: str) -> Dict[str, Any]:
    """读取协议本地 resources/ip_lists/ 下的 IP 文件，返回 IP 列表、总数与地理分布统计。

    数据源为 ``attack_resources/{proto}/resources/ip_lists/`` 下的所有 .txt 文件，
    空目录时返回友好空状态（``ips: [], total: 0``），不报错。
    """
    sources = _list_server_file_sources(method)
    ips: List[str] = []
    seen: set = set()
    for item in sources:
        full_path = item.get("full_path", "")
        if not full_path:
            continue
        for ip in read_server_entries_from_file(Path(full_path)):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    if not ips:
        return {
            "ips": [],
            "total": 0,
            "geo_distribution": [],
            "located_count": 0,
            "unresolved_count": 0,
        }

    geo_result = _build_geo_points(method, entries=ips)
    return {
        "ips": ips,
        "total": len(ips),
        "geo_distribution": geo_result.get("areas", []),
        "located_count": geo_result.get("located_count", 0),
        "unresolved_count": geo_result.get("unresolved_count", 0),
    }


def list_server_source_paths(method: str) -> List[Path]:
    return [Path(item["full_path"]) for item in _list_server_file_sources(method)]


def count_server_entries_in_file(path: Path) -> int:
    return count_ip_entries(path)


def resolve_server_source(
    method: str, source: Optional[str] = None
) -> Optional[Path]:
    resources = _list_server_file_sources(method)
    if not resources:
        return None
    if source:
        resolved = resolve_protocol_local_resource_path(
            method, source, _c.ATTACK_RESOURCES_ROOT
        )
        if resolved is not None:
            return resolved
        source_name = Path(str(source)).name
        for item in resources:
            if item["name"] == source_name:
                return Path(item["full_path"])
        return None
    return Path(resources[0]["full_path"])


def resolve_server_sources(
    method: str, sources: Optional[List[str]] = None
) -> List[Path]:
    resources = _list_server_file_sources(method)
    if not resources:
        return []
    if not sources:
        return [Path(item["full_path"]) for item in resources]

    resolved: List[Path] = []
    seen = set()
    for source in sources:
        path = resolve_server_source(method, source)
        if path is None:
            continue
        if path not in seen:
            seen.add(path)
            resolved.append(path)
    return resolved or [Path(item["full_path"]) for item in resources]


def get_effective_server_file(
    method: str, source: Optional[str] = None
) -> str:
    resolved = resolve_server_source(method, source)
    if resolved is not None:
        return str(resolved)
    return get_server_file(method)


def read_server_entries_from_file(path: Path) -> List[str]:
    if not path.exists():
        return []
    servers = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                servers.append(line)
    return servers


def read_server_entries(
    method: str, source_files: Optional[List[Path]] = None
) -> List[str]:
    source_paths = (
        source_files if source_files is not None else resolve_server_sources(method)
    )
    servers = []
    seen = set()
    for path in source_paths:
        for server in read_server_entries_from_file(path):
            if server not in seen:
                seen.add(server)
                servers.append(server)
    return servers
