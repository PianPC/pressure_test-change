"""协议独立的质量 IP 池聚合与查询工具。

当前资源池页面所有协议曾共享同一个文件夹，但不同协议的优质 IP 不一样，
因此本模块为每个协议（tcp、dns、memcached、ntp）维护独立的质量 IP 池。

``aggregate_quality_ips`` 读取任务产出的 ``qualified_ips.txt``，与现有
``attack_resources/{proto}/qualified_pool/qualified_pool.txt`` 合并去重后写回，
实现跨任务的质量 IP 累积。``list_qualified_pool_ips`` 用于读取各协议质量池
的当前状态（IP 列表、总数、文件大小、是否存在等）。
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# attack_resources 根目录（本文件位于 attack_resources/shared/qualified_pool.py）
ATTACK_RESOURCES_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUPPORTED_PROTOCOLS = ("tcp", "dns", "memcached", "ntp")

QUALIFIED_POOL_FILENAME = "qualified_pool.txt"


def _qualified_pool_path(proto: str) -> str:
    """返回指定协议的质量 IP 池文件路径（基于 ATTACK_RESOURCES_ROOT 拼接）。"""
    return os.path.join(
        ATTACK_RESOURCES_ROOT, proto, "qualified_pool", QUALIFIED_POOL_FILENAME
    )


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


def aggregate_quality_ips(proto: str, task_qualified_ips_path: str) -> Dict[str, Any]:
    """将任务产出的质量 IP 聚合到指定协议的质量池中。

    读取 ``task_qualified_ips_path`` 指向的 ``qualified_ips.txt``，与现有
    ``attack_resources/{proto}/qualified_pool/qualified_pool.txt`` 合并去重后写回。
    IP 去重按行处理，去除空行和以 # 开头的注释行。

    Args:
        proto: 协议名称（tcp/dns/memcached/ntp）。
        task_qualified_ips_path: 任务产出的 ``qualified_ips.txt`` 路径。

    Returns:
        包含 ``added_count``、``total_count``、``pool_path`` 的字典；
        当任务产物文件不存在时，额外返回 ``error`` 字段且计数为 0。
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
            "error": "task file not found",
        }

    logger.info(
        "aggregating quality IPs for proto=%s from %s into %s",
        proto,
        task_qualified_ips_path,
        pool_path,
    )

    existing_ips = _read_ip_lines(pool_path)
    new_ips = _read_ip_lines(task_qualified_ips_path)

    merged: List[str] = list(existing_ips)
    seen = set(existing_ips)
    added_count = 0
    for ip in new_ips:
        if ip in seen:
            continue
        seen.add(ip)
        merged.append(ip)
        added_count += 1

    pool_dir = os.path.dirname(pool_path)
    if pool_dir:
        os.makedirs(pool_dir, exist_ok=True)

    with open(pool_path, "w", encoding="utf-8") as handle:
        for ip in merged:
            handle.write(ip + "\n")

    logger.info(
        "aggregated %d new IPs for proto=%s, total=%d",
        added_count,
        proto,
        len(merged),
    )

    return {
        "added_count": added_count,
        "total_count": len(merged),
        "pool_path": pool_path,
    }


def list_qualified_pool_ips(proto: str) -> Dict[str, Any]:
    """读取指定协议质量池的当前 IP 列表与元信息。

    Args:
        proto: 协议名称（tcp/dns/memcached/ntp）。

    Returns:
        包含 ``ips``、``total``、``pool_path``、``file_size_bytes``、
        ``exists`` 的字典。池文件不存在时 ``ips`` 为空列表、``exists`` 为 False。
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
        }

    ips = _read_ip_lines(abs_pool_path)
    file_size_bytes = os.path.getsize(abs_pool_path)

    logger.debug(
        "listed qualified pool for proto=%s: %d IPs, %d bytes",
        proto,
        len(ips),
        file_size_bytes,
    )

    return {
        "ips": ips,
        "total": len(ips),
        "pool_path": abs_pool_path,
        "file_size_bytes": file_size_bytes,
        "exists": True,
    }
