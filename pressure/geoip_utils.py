"""GEOIP 查询、缓存与地理聚合工具。

拆分前位于 ``app.py`` 第 528-817 行。对外 API 保持不变：

- :func:`build_geo_points` 由 :mod:`pressure.servers` 与路由 ``/api/servers/<method>/geo`` 共用
- :func:`normalize_geo_record`、:func:`load_geoip_cache`、:func:`save_geoip_cache`
  等工具函数在模块内部使用，同时也通过 :mod:`pressure.__init__` 暴露以便未来复用
"""

import ipaddress
import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import constants as _c

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # pragma: no cover - 依赖安装由部署阶段保障
    geoip2 = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 缓存读写
# ---------------------------------------------------------------------------

def load_geoip_cache() -> Dict[str, Any]:
    if not os.path.exists(_c.GEOIP_CACHE_FILE):
        return {}
    try:
        with open(_c.GEOIP_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        logger.warning("GeoIP cache could not be loaded", exc_info=True)
        return {}


def save_geoip_cache(cache: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_c.GEOIP_CACHE_FILE), exist_ok=True)
    tmp_file = f"{_c.GEOIP_CACHE_FILE}.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, _c.GEOIP_CACHE_FILE)


# ---------------------------------------------------------------------------
# 域名 / IP 基础校验
# ---------------------------------------------------------------------------

def resolve_public_ip(entry: str) -> Tuple[Optional[str], Optional[str]]:
    target = entry.strip()
    if not target:
        return None, "empty"
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return None, "dns_failed"
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None, "invalid_ip"
    if not parsed.is_global:
        return None, "private_or_reserved"
    return ip, None


# ---------------------------------------------------------------------------
# 地理记录归一化
# ---------------------------------------------------------------------------

def normalize_geo_record(geo: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(geo)
    country = (normalized.get("country") or "").strip()
    country_code = (
        normalized.get("country_code") or normalized.get("countryCode") or ""
    ).strip().upper()
    region = (
        normalized.get("region") or normalized.get("regionName") or ""
    ).strip()
    region_code = (
        normalized.get("region_code") or normalized.get("regionCode") or ""
    ).strip().upper()
    if not country_code and country:
        country_code = _c.COUNTRY_NAME_TO_CODE.get(country.upper(), "")

    china_alias = None
    for value in (country_code, country, region_code, region):
        key = str(value or "").strip().upper()
        if key in _c.CHINA_AREA_ALIASES:
            china_alias = _c.CHINA_AREA_ALIASES[key]
            break

    if china_alias:
        country = "China"
        country_code = "CN"
        region_code = region_code or china_alias[0]
        region = region or china_alias[1]

    normalized["country"] = country
    normalized["country_code"] = country_code
    normalized["region"] = region
    normalized["region_code"] = region_code
    normalized.pop("countryCode", None)
    normalized.pop("regionName", None)
    normalized.pop("regionCode", None)
    return normalized


def is_geo_cache_complete(cached: Dict[str, Any]) -> bool:
    normalized = normalize_geo_record(cached)
    if normalized.get("lat") is None or normalized.get("lon") is None:
        return False
    if not normalized.get("country") or not normalized.get("country_code"):
        return False
    if normalized.get("country_code") in _c.SUBDIVISION_COUNTRY_CODES:
        return bool(normalized.get("region") or normalized.get("region_code"))
    return True


# ---------------------------------------------------------------------------
# 查询实现（本地库 -> ip-api 回退）
# ---------------------------------------------------------------------------

def query_geoip_local_batch(
    ips: List[str],
) -> Dict[str, Dict[str, Any]]:
    if not ips or geoip2 is None or not os.path.exists(_c.GEOIP_LOCAL_DB_FILE):
        return {}
    located: Dict[str, Dict[str, Any]] = {}
    try:
        reader = geoip2.database.Reader(_c.GEOIP_LOCAL_DB_FILE)
    except (OSError, ValueError) as exc:
        logger.warning("Local GeoIP database could not be opened: %s", exc)
        return {}
    try:
        for ip in ips:
            try:
                result = reader.city(ip)
            except (geoip2.errors.AddressNotFoundError, ValueError):
                continue
            region = result.subdivisions.most_specific
            geo = normalize_geo_record(
                {
                    "ip": ip,
                    "lat": result.location.latitude,
                    "lon": result.location.longitude,
                    "country": result.country.name or "",
                    "country_code": result.country.iso_code or "",
                    "region": region.name or "",
                    "region_code": region.iso_code or "",
                    "city": result.city.name or "",
                    "isp": "",
                    "cached_at": time.time(),
                }
            )
            if geo.get("lat") is not None and geo.get("lon") is not None:
                located[ip] = geo
    finally:
        reader.close()
    return located


def query_geoip_batch(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    if not ips:
        return {}
    url = "http://ip-api.com/batch?fields=status,message,query,lat,lon,country,countryCode,region,regionName,city,isp"
    payload = json.dumps(ips).encode("utf-8")
    request_obj = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request_obj, timeout=8) as response:
        body = response.read().decode("utf-8")
    results = json.loads(body)
    if not isinstance(results, list):
        raise ValueError("GeoIP API returned an unexpected response")
    located: Dict[str, Dict[str, Any]] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        ip = item.get("query")
        if (
            item.get("status") == "success"
            and ip
            and item.get("lat") is not None
            and item.get("lon") is not None
        ):
            located[ip] = normalize_geo_record(
                {
                    "ip": ip,
                    "lat": float(item.get("lat")),
                    "lon": float(item.get("lon")),
                    "country": item.get("country") or "",
                    "country_code": item.get("countryCode") or "",
                    "region": item.get("regionName") or "",
                    "region_code": item.get("region") or "",
                    "city": item.get("city") or "",
                    "isp": item.get("isp") or "",
                    "cached_at": time.time(),
                }
            )
    return located


# ---------------------------------------------------------------------------
# 地理区域 / 点位 聚合
# ---------------------------------------------------------------------------

def build_geo_areas(
    points: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    area_map: Dict[str, Dict[str, Any]] = {}
    for point in points:
        geo = normalize_geo_record(point)
        country_code = geo.get("country_code") or ""
        country = geo.get("country") or "Unknown"
        region_code = geo.get("region_code") or ""
        region = geo.get("region") or ""
        entries = (
            geo.get("entries") if isinstance(geo.get("entries"), list) else []
        )

        if country_code in _c.SUBDIVISION_COUNTRY_CODES and (
            region_code or region
        ):
            level = "region"
            area_code = (
                f"{country_code}-{region_code}"
                if region_code
                else f"{country_code}:{region.lower()}"
            )
            area_name = region or area_code
        else:
            level = "country"
            area_code = country_code or country.lower()
            area_name = country

        key = f"{level}:{area_code}"
        area = area_map.setdefault(
            key,
            {
                "level": level,
                "area_code": area_code,
                "name": area_name,
                "country_code": country_code,
                "country": country,
                "region_code": region_code if level == "region" else "",
                "region": region if level == "region" else "",
                "resource_count": 0,
                "ips": [],
                "entries": [],
            },
        )
        area["resource_count"] += 1
        if geo.get("ip") and geo.get("ip") not in area["ips"]:
            area["ips"].append(geo.get("ip"))
        for entry in entries:
            if entry not in area["entries"]:
                area["entries"].append(entry)

    return sorted(
        area_map.values(),
        key=lambda item: (
            -int(item.get("resource_count") or 0),
            item.get("country") or "",
            item.get("region") or "",
        ),
    )


def build_geo_points(
    method: str,
    source_files: Optional[List[Path]] = None,
    entries: Optional[List[str]] = None,
) -> Dict[str, Any]:
    # servers.py 模块的延迟导入依赖在此保持存在，不可删除或改名
    if entries is None:
        from .servers import read_server_entries

        entries = read_server_entries(method, source_files=source_files)
    cache = load_geoip_cache()
    now = time.time()
    unresolved: List[Dict[str, Any]] = []
    ip_entries: Dict[str, List[str]] = {}

    for entry in entries:
        ip, reason = resolve_public_ip(entry)
        if not ip:
            unresolved.append({"entry": entry, "reason": reason})
            continue
        ip_entries.setdefault(ip, []).append(entry)

    points_by_ip: Dict[str, Dict[str, Any]] = {}
    stale_points: Dict[str, Dict[str, Any]] = {}
    missing_ips: List[str] = []
    for ip in ip_entries:
        cached = cache.get(ip)
        if isinstance(cached, dict) and is_geo_cache_complete(cached):
            cached = normalize_geo_record(cached)
            if now - float(cached.get("cached_at", 0)) <= _c.GEOIP_CACHE_TTL_SECONDS:
                points_by_ip[ip] = cached
            else:
                stale_points[ip] = cached
                missing_ips.append(ip)
        else:
            if (
                isinstance(cached, dict)
                and cached.get("lat") is not None
                and cached.get("lon") is not None
            ):
                stale_points[ip] = normalize_geo_record(cached)
            missing_ips.append(ip)

    api_failed = False
    for index in range(0, len(missing_ips), _c.GEOIP_BATCH_SIZE):
        batch = missing_ips[index : index + _c.GEOIP_BATCH_SIZE]
        located = query_geoip_local_batch(batch)
        api_lookup_failed = False
        unresolved_batch = [ip for ip in batch if ip not in located]
        if unresolved_batch:
            try:
                located.update(query_geoip_batch(unresolved_batch))
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                api_failed = True
                api_lookup_failed = True
                logger.warning("GeoIP lookup failed: %s", exc)
        try:
            for ip, geo in located.items():
                cache[ip] = geo
                points_by_ip[ip] = geo
                stale_points.pop(ip, None)
            for ip in batch:
                if ip not in located and ip not in stale_points:
                    unresolved.append(
                        {
                            "entry": ip_entries[ip][0],
                            "ip": ip,
                            "reason": (
                                "geo_api_failed"
                                if api_lookup_failed
                                else "geo_not_found"
                            ),
                        }
                    )
            for ip in batch:
                if ip in stale_points:
                    points_by_ip[ip] = stale_points[ip]
        except (OSError, ValueError) as exc:
            api_failed = True
            logger.warning("GeoIP processing failed: %s", exc)
            for ip in batch:
                if ip in stale_points:
                    points_by_ip[ip] = stale_points[ip]
                else:
                    unresolved.append(
                        {
                            "entry": ip_entries[ip][0],
                            "ip": ip,
                            "reason": "geo_api_failed",
                        }
                    )

    if missing_ips:
        try:
            save_geoip_cache(cache)
        except OSError:
            logger.warning("GeoIP cache could not be saved", exc_info=True)

    points: List[Dict[str, Any]] = []
    for ip, geo in points_by_ip.items():
        geo = normalize_geo_record(geo)
        points.append(
            {
                "ip": ip,
                "entries": ip_entries.get(ip, [ip]),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "country": geo.get("country") or "",
                "country_code": geo.get("country_code") or "",
                "region": geo.get("region") or "",
                "region_code": geo.get("region_code") or "",
                "city": geo.get("city") or "",
                "isp": geo.get("isp") or "",
                "stale": ip in stale_points,
            }
        )
    areas = build_geo_areas(points)

    return {
        "success": True,
        "protocol": method,
        "total": len(entries),
        "located_count": len(points),
        "unresolved_count": len(unresolved),
        "area_count": len(areas),
        "areas": areas,
        "points": points,
        "unresolved": unresolved,
        "geo_api_degraded": api_failed,
    }
