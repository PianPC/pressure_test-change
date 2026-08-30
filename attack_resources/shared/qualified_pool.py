"""协议独立的质量 IP 池聚合与查询工具。

当前资源池页面所有协议曾共享同一个文件夹，但不同协议的优质 IP 不一样，
因此本模块为每个协议（tcp、dns、memcached、ntp）维护独立的质量 IP 池。

``aggregate_quality_ips`` 读取任务产出的 ``qualified_ips.txt``，与现有
``attack_resources/{proto}/qualified_pool/qualified_pool.txt`` 合并去重后写回，
实现跨任务的质量 IP 累积。``list_qualified_pool_ips`` 用于读取各协议质量池
的当前状态（IP 列表、总数、文件大小、是否存在等）。

**质量池新鲜度机制（论文对齐）**：
中间盒流失率高（论文 209 个目标 4 天内 11.9% 停止响应），因此本模块通过
与 pool 同名的 ``.metadata.json`` 元数据文件记录每个 IP 的最后验证时间，
默认 7 天有效期。过期 IP 在读取/聚合时会被标记并从有效列表中剔除，但
原始 txt 文件仍保持"每行纯 IP"的兼容格式，不破坏既有文件解析与下游流程。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# attack_resources 根目录（本文件位于 attack_resources/shared/qualified_pool.py）
ATTACK_RESOURCES_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUPPORTED_PROTOCOLS = ("tcp", "dns", "memcached", "ntp")

QUALIFIED_POOL_FILENAME = "qualified_pool.txt"
METADATA_SUFFIX = ".metadata.json"

# 默认有效期：7 天（论文数据显示 4 天内已有 11.9% 流失，取 1 周作为合理窗口）
DEFAULT_VALIDITY_DAYS = 7


def _qualified_pool_path(proto: str) -> str:
    """返回指定协议的质量 IP 池文件路径（基于 ATTACK_RESOURCES_ROOT 拼接）。"""
    return os.path.join(
        ATTACK_RESOURCES_ROOT, proto, "qualified_pool", QUALIFIED_POOL_FILENAME
    )


def _metadata_path(pool_path: str) -> str:
    """返回质量池文件对应的元数据文件路径（不破坏 txt 的兼容性）。"""
    return pool_path + METADATA_SUFFIX


def _load_metadata(pool_path: str) -> Dict[str, Any]:
    """加载质量池元数据。文件不存在或格式错误时返回默认空结构。"""
    meta_path = _metadata_path(pool_path)
    default: Dict[str, Any] = {
        "validity_days": DEFAULT_VALIDITY_DAYS,
        "ips": {},  # {ip: {"verified_at": float}}
    }
    if not os.path.isfile(meta_path):
        return default
    try:
        with open(meta_path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("failed to load metadata %s: %s", meta_path, exc)
        return default
    if not isinstance(raw, dict):
        return default
    if "validity_days" not in raw or not isinstance(raw.get("validity_days"), (int, float)):
        raw["validity_days"] = DEFAULT_VALIDITY_DAYS
    if not isinstance(raw.get("ips"), dict):
        raw["ips"] = {}
    return raw


def _save_metadata(pool_path: str, meta: Dict[str, Any]) -> None:
    """将元数据原子写入磁盘，失败仅记录日志不中断主流程。"""
    meta_path = _metadata_path(pool_path)
    meta_dir = os.path.dirname(meta_path)
    if meta_dir:
        os.makedirs(meta_dir, exist_ok=True)
    tmp_path = meta_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(meta, handle, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, meta_path)
    except OSError as exc:
        logger.warning("failed to save metadata %s: %s", meta_path, exc)
        try:
            if os.path.isfile(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def _is_expired(verified_at: float, validity_days: int | float) -> bool:
    """基于 verified_at 判断 IP 是否已过期。"""
    if not verified_at:
        return True  # 没有验证时间视为已过期
    threshold = float(validity_days) * 86400.0
    return (time.time() - float(verified_at)) > threshold


def _read_ip_lines(file_path: str) -> List[str]:
    """从文件中读取 IP 行，跳过空行和以 # 开头的注释行，并去重保持出现顺序。"""
    if not os.path.isfile(file_path):
        return []
    seen = set()
    result: List[str] = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            if line in seen:
                continue
            seen.add(line)
            result.append(line)
    return result


def _write_pool_file(pool_path: str, ips: List[str]) -> None:
    """写回质量池 txt 文件，保持"每行纯 IP"兼容格式。"""
    pool_dir = os.path.dirname(pool_path)
    if pool_dir:
        os.makedirs(pool_dir, exist_ok=True)
    with open(pool_path, "w", encoding="utf-8") as handle:
        for ip in ips:
            handle.write(ip + "\n")


def _sync_to_ip_lists(proto: str, pool_path: str) -> str:
    """同步质量池文件到协议 resources/ip_lists 目录（供资源管理 UI 读取）。"""
    sync_target = os.path.join(
        ATTACK_RESOURCES_ROOT, proto, "resources", "ip_lists", QUALIFIED_POOL_FILENAME
    )
    synced_path = ""
    try:
        sync_dir = os.path.dirname(sync_target)
        if sync_dir:
            os.makedirs(sync_dir, exist_ok=True)
        shutil.copy2(pool_path, sync_target)
        synced_path = os.path.abspath(sync_target)
        logger.info("synced qualified pool to %s", synced_path)
    except Exception as sync_err:
        logger.warning("failed to sync qualified pool to %s: %s", sync_target, sync_err)
    return synced_path


def aggregate_quality_ips(proto: str, task_qualified_ips_path: str) -> Dict[str, Any]:
    """将任务产出的质量 IP 聚合到指定协议的质量池中。

    读取 ``task_qualified_ips_path`` 指向的 ``qualified_ips.txt``，与现有
    ``attack_resources/{proto}/qualified_pool/qualified_pool.txt`` 合并去重后写回。
    新增 IP 的 verified_at 设置为当前时间，已存在 IP 保留历史验证时间；
    合并时同步剔除已过期的 IP（保持质量池有效性）。
    """
    pool_path = _qualified_pool_path(proto)

    if not os.path.isfile(task_qualified_ips_path):
        logger.warning(
            "task qualified_ips file not found: %s (proto=%s)",
            task_qualified_ips_path,
            proto,
        )
        return {
            "added_count": 0,
            "total_count": 0,
            "pool_path": pool_path,
            "synced_path": "",
            "error": "task file not found",
        }

    logger.info(
        "aggregating quality IPs for proto=%s from %s into %s",
        proto,
        task_qualified_ips_path,
        pool_path,
    )

    meta = _load_metadata(pool_path)
    validity_days = float(meta.get("validity_days", DEFAULT_VALIDITY_DAYS))
    ip_meta: Dict[str, Dict[str, Any]] = meta.setdefault("ips", {})

    existing_ips = _read_ip_lines(pool_path)
    new_ips = _read_ip_lines(task_qualified_ips_path)

    now = time.time()
    merged: List[str] = []
    seen = set()
    added_count = 0
    expired_count = 0

    # 先处理已有 IP，过滤掉过期条目
    for ip in existing_ips:
        if ip in seen:
            continue
        verified_at = float(ip_meta.get(ip, {}).get("verified_at", 0.0))
        if verified_at and _is_expired(verified_at, validity_days):
            expired_count += 1
            continue  # 过期 IP 不再进入新的 pool
        seen.add(ip)
        merged.append(ip)

    # 再追加新 IP（以当前时间作为首次验证时间）
    for ip in new_ips:
        if ip in seen:
            # 已存在的 IP 若来自新任务，刷新验证时间
            entry = ip_meta.setdefault(ip, {})
            entry["verified_at"] = now
            continue
        seen.add(ip)
        merged.append(ip)
        added_count += 1
        ip_meta[ip] = {"verified_at": now}

    # 清理不在 merged 列表中的陈旧元数据项
    meta["ips"] = {ip: info for ip, info in ip_meta.items() if ip in seen}

    _write_pool_file(pool_path, merged)
    _save_metadata(pool_path, meta)

    logger.info(
        "aggregated %d new IPs for proto=%s, total=%d, expired_removed=%d",
        added_count,
        proto,
        len(merged),
        expired_count,
    )

    synced_path = _sync_to_ip_lists(proto, pool_path)

    return {
        "added_count": added_count,
        "total_count": len(merged),
        "expired_removed_count": expired_count,
        "pool_path": pool_path,
        "synced_path": synced_path,
        "validity_days": validity_days,
    }


def add_ips_to_pool(proto: str, ips: List[str]) -> Dict[str, Any]:
    """手动添加选中的 IP 到指定协议的质量池。

    与 ``aggregate_quality_ips`` 不同，此函数直接接收 IP 列表（而非从文件读取），
    适用于前端"选取优质 IP 添加到资源池"的场景。手动添加的 IP 同样会写入
    verified_at，并在合并时剔除过期条目。
    """
    pool_path = _qualified_pool_path(proto)
    meta = _load_metadata(pool_path)
    validity_days = float(meta.get("validity_days", DEFAULT_VALIDITY_DAYS))
    ip_meta: Dict[str, Dict[str, Any]] = meta.setdefault("ips", {})

    existing_ips = _read_ip_lines(pool_path)

    now = time.time()
    merged: List[str] = []
    seen = set()
    added_count = 0
    expired_count = 0

    for ip in existing_ips:
        if ip in seen:
            continue
        verified_at = float(ip_meta.get(ip, {}).get("verified_at", 0.0))
        if verified_at and _is_expired(verified_at, validity_days):
            expired_count += 1
            continue
        seen.add(ip)
        merged.append(ip)

    for raw_ip in ips:
        ip = raw_ip.strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        merged.append(ip)
        added_count += 1
        ip_meta[ip] = {"verified_at": now}

    meta["ips"] = {ip: info for ip, info in ip_meta.items() if ip in seen}

    _write_pool_file(pool_path, merged)
    _save_metadata(pool_path, meta)

    logger.info(
        "manually added %d IPs for proto=%s, total=%d, expired_removed=%d",
        added_count,
        proto,
        len(merged),
        expired_count,
    )

    synced_path = _sync_to_ip_lists(proto, pool_path)

    return {
        "added_count": added_count,
        "total_count": len(merged),
        "expired_removed_count": expired_count,
        "pool_path": os.path.abspath(pool_path),
        "synced_path": synced_path,
        "validity_days": validity_days,
    }


def list_qualified_pool_ips(proto: str) -> Dict[str, Any]:
    """读取指定协议质量池的当前 IP 列表与元信息。

    返回结构保持向后兼容：保留 ``ips``、``total``、``pool_path``、
    ``file_size_bytes``、``exists`` 字段；同时额外返回每个 IP 的验证时间
    与过期状态，供前端展示或进一步过滤使用。
    """
    pool_path = _qualified_pool_path(proto)
    abs_pool_path = os.path.abspath(pool_path)
    exists = os.path.isfile(abs_pool_path)

    if not exists:
        logger.debug(
            "qualified pool not exists for proto=%s at %s",
            proto,
            abs_pool_path,
        )
        return {
            "ips": [],
            "total": 0,
            "pool_path": abs_pool_path,
            "file_size_bytes": 0,
            "exists": False,
            "validity_days": DEFAULT_VALIDITY_DAYS,
            "expired_count": 0,
            "ip_details": {},  # {ip: {"verified_at": ts, "expired": bool, "age_days": float}}
        }

    meta = _load_metadata(pool_path)
    validity_days = float(meta.get("validity_days", DEFAULT_VALIDITY_DAYS))
    ip_meta = meta.get("ips", {})

    raw_ips = _read_ip_lines(abs_pool_path)
    now = time.time()

    active_ips: List[str] = []
    expired_count = 0
    ip_details: Dict[str, Dict[str, Any]] = {}

    for ip in raw_ips:
        verified_at = float(ip_meta.get(ip, {}).get("verified_at", 0.0))
        expired = (not verified_at) or _is_expired(verified_at, validity_days)
        age_days = ((now - verified_at) / 86400.0) if verified_at else None
        details = {
            "verified_at": verified_at if verified_at else None,
            "verified_at_iso": (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(verified_at))
                if verified_at
                else None
            ),
            "expired": expired,
            "age_days": round(age_days, 2) if age_days is not None else None,
        }
        ip_details[ip] = details
        if expired:
            expired_count += 1
        else:
            active_ips.append(ip)

    file_size_bytes = os.path.getsize(abs_pool_path)

    logger.debug(
        "listed qualified pool for proto=%s: %d active IPs, %d expired, %d bytes",
        proto,
        len(active_ips),
        expired_count,
        file_size_bytes,
    )

    return {
        "ips": active_ips,               # 兼容字段：仅未过期 IP
        "total": len(active_ips),        # 兼容字段：仅未过期计数
        "all_ips": raw_ips,              # 完整列表（含过期，供调试 UI）
        "all_total": len(raw_ips),
        "expired_count": expired_count,
        "pool_path": abs_pool_path,
        "file_size_bytes": file_size_bytes,
        "exists": True,
        "validity_days": validity_days,
        "ip_details": ip_details,        # 每个 IP 的验证时间与过期状态
    }
