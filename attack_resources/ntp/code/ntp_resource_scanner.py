#!/usr/bin/env python3
"""
NTP 攻击资源扫描器 — 基于 MON_GETLIST 放大率测量的优质 NTP 反射器发现工具

核心逻辑（源自手动探测脚本 ntp_monlist_batch.py / ntp_monlist.py / y_ntp.py）：
  1. 加载候选 NTP 服务器 IP 列表
  2. 对每台服务器发送 NTP probe（time request，验证存活）
  3. 对存活服务器发送 MON_GETLIST (Mode=7, Opcode=42) 请求
  4. 计算 放大率 = 响应总字节数 / 请求字节数
  5. 按放大率阈值、可用性阈值过滤，产出"优质攻击资源"
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


# ── 常量 ──────────────────────────────────────────────

# 支持的探测动作
PROBE_ACTION_PROBE = "probe"       # 仅存活探测（NTP time request）
PROBE_ACTION_MONLIST = "monlist"   # MON_GETLIST 放大率测量
PROBE_ACTION_BOTH = "both"         # 先 probe 筛选存活，再 monlist 测量

PROBE_ACTIONS = {
    PROBE_ACTION_PROBE: "存活探测",
    PROBE_ACTION_MONLIST: "Monlist放大测量",
    PROBE_ACTION_BOTH: "存活+放大测量",
}

DEFAULT_PROBE_ACTION = PROBE_ACTION_BOTH

DEFAULT_TIMEOUT_SEC = 3.0
DEFAULT_CONCURRENCY = 50
DEFAULT_MIN_AMPLIFICATION = 50.0     # 低于此倍数的直接丢弃
DEFAULT_MIN_AVAILABILITY = 30.0      # 应答成功率低于此值的丢弃
DEFAULT_NTP_PORT = 123

# NTP Monlist 请求包（48字节）
# LI=0, VN=3, Mode=7 (0x17) | 0x00 | 0x03 | Opcode=42 (0x2a)
MONLIST_REQUEST = b'\x17\x00\x03\x2a' + b'\x00' * 44

# NTP Probe 请求包（48字节）
# LI=0, VN=4, Mode=3 (client, 0x1b)
PROBE_REQUEST = b'\x1b' + b'\x00' * 47


# ── 数据类 ────────────────────────────────────────────

@dataclass
class ServerResult:
    ip: str
    action: str                   # probe / monlist
    responded: bool
    request_bytes: int = 0
    response_bytes: int = 0
    amplification_factor: float = 0.0
    latency_ms: float = 0.0
    response_packets: int = 0     # monlist 响应包数量
    error: str = ""


@dataclass
class ScanConfig:
    """一次资源扫描的配置"""
    ip_file: str = ""                              # 输入 IP 列表文件
    output_dir: str = ""                           # 结果输出目录
    probe_action: str = DEFAULT_PROBE_ACTION       # 探测动作
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    concurrency: int = DEFAULT_CONCURRENCY
    min_amplification: float = DEFAULT_MIN_AMPLIFICATION
    min_availability: float = DEFAULT_MIN_AVAILABILITY
    max_ips: int = 0                               # 0 = 不限制
    ntp_port: int = DEFAULT_NTP_PORT


# ── 工具函数 ──────────────────────────────────────────

def _build_monlist_request() -> bytes:
    """构建 NTP MON_GETLIST 请求包（Mode=7, Opcode=42）"""
    return MONLIST_REQUEST


def _build_probe_request() -> bytes:
    """构建 NTP 标准时间请求包（Mode=3, client）"""
    return PROBE_REQUEST


# ── 单 IP 测试 ────────────────────────────────────────

def _test_probe(
    ip: str,
    port: int,
    timeout: float,
) -> ServerResult:
    """对单个 NTP 服务器做存活探测，返回 ServerResult"""
    result = ServerResult(
        ip=ip,
        action=PROBE_ACTION_PROBE,
        responded=False,
    )
    query_data = _build_probe_request()
    query_size = len(query_data)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.sendto(query_data, (ip, port))
        data, _ = sock.recvfrom(65535)
        end = time.time()
        sock.close()

        resp_size = len(data)
        if resp_size >= 48:  # NTP 报文最小长度
            result.responded = True
            result.request_bytes = query_size
            result.response_bytes = resp_size
            result.amplification_factor = round(resp_size / query_size, 2) if query_size > 0 else 0
            result.latency_ms = round((end - start) * 1000, 1)
    except socket.timeout:
        result.error = "timeout"
        result.request_bytes = query_size
    except Exception as e:
        result.error = str(e)[:80]
        result.request_bytes = query_size
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


def _test_monlist(
    ip: str,
    port: int,
    timeout: float,
) -> ServerResult:
    """对单个 NTP 服务器做 MON_GETLIST 放大率测量，返回 ServerResult"""
    result = ServerResult(
        ip=ip,
        action=PROBE_ACTION_MONLIST,
        responded=False,
    )
    query_data = _build_monlist_request()
    query_size = len(query_data)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.sendto(query_data, (ip, port))

        # 收集所有响应包（monlist 可能分多个包返回）
        total_resp_size = 0
        packet_count = 0
        end_time = start + timeout

        while time.time() < end_time:
            try:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(min(remaining, 0.5))
                data, addr = sock.recvfrom(65535)
                if addr[0] == ip and addr[1] == port:
                    total_resp_size += len(data)
                    packet_count += 1
            except socket.timeout:
                break

        end = time.time()
        sock.close()

        if packet_count > 0 and total_resp_size > 0:
            result.responded = True
            result.request_bytes = query_size
            result.response_bytes = total_resp_size
            result.amplification_factor = round(total_resp_size / query_size, 2) if query_size > 0 else 0
            result.latency_ms = round((end - start) * 1000, 1)
            result.response_packets = packet_count
    except socket.timeout:
        result.error = "timeout"
        result.request_bytes = query_size
    except Exception as e:
        result.error = str(e)[:80]
        result.request_bytes = query_size
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return result


# ── NTP 资源扫描器 ────────────────────────────────────

class NTPResourceScanner:
    """NTP 攻击资源扫描器 —— 多 IP 放大率测量流水线"""

    def __init__(self):
        self._is_running = False
        self._stop_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._scan_thread: Optional[threading.Thread] = None

        # 实时统计
        self.stats: Dict[str, Any] = {
            "total_ips": 0,
            "total_tasks": 0,
            "tested": 0,
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
        started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self.stats = {
            "total_ips": 0, "total_tasks": 0, "tested": 0, "responded": 0, "failed": 0,
            "qualified": 0, "elapsed_sec": 0.0, "current_ip": "",
            "progress_percent": 0.0, "stage": "loading", "current_stage": "loading",
            "status": "running", "started_at": started_at, "ended_at": None, "stages": {},
            "config": {
                "ip_file": os.path.basename(config.ip_file),
                "probe_action": config.probe_action,
                "timeout_sec": config.timeout_sec,
                "concurrency": config.concurrency,
                "min_amplification": config.min_amplification,
                "min_availability": config.min_availability,
                "max_ips": config.max_ips,
                "ntp_port": config.ntp_port,
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

            # 根据探测动作计算总任务数
            if config.probe_action == PROBE_ACTION_BOTH:
                total_tasks = len(ips) * 2  # probe + monlist
            else:
                total_tasks = len(ips)

            with self._stats_lock:
                self.stats["total_ips"] = len(ips)
                self.stats["total_tasks"] = total_tasks
            self._update_stage("loading", "completed", total_ips=len(ips))
            self._log(f"✅ 加载 {len(ips)} 个候选 IP，探测动作: {PROBE_ACTIONS.get(config.probe_action, config.probe_action)}")

            # Stage 2: 执行 NTP 探测
            self._update_stage("scanning", "running")
            self._log("🔍 开始 NTP 探测 …")

            semaphore = threading.Semaphore(config.concurrency)
            results_lock = threading.Lock()

            def _worker(ip: str, action: str):
                semaphore.acquire()
                try:
                    if self._stop_event.is_set():
                        return
                    with self._stats_lock:
                        self.stats["current_ip"] = ip

                    if action == PROBE_ACTION_PROBE:
                        res = _test_probe(ip, config.ntp_port, config.timeout_sec)
                    else:
                        res = _test_monlist(ip, config.ntp_port, config.timeout_sec)

                    with results_lock:
                        self._all_results.append(res)
                        cnt = len(self._all_results)
                        self.stats["tested"] = cnt
                        self.stats["progress_percent"] = round(
                            cnt / max(1, self.stats["total_tasks"]) * 100, 1
                        )
                        if res.responded:
                            self.stats["responded"] = self.stats.get("responded", 0) + 1
                        else:
                            self.stats["failed"] = self.stats.get("failed", 0) + 1
                finally:
                    semaphore.release()

            # 模式1: 仅 probe
            if config.probe_action == PROBE_ACTION_PROBE:
                threads = []
                for ip in ips:
                    if self._stop_event.is_set():
                        break
                    t = threading.Thread(target=_worker, args=(ip, PROBE_ACTION_PROBE), daemon=True)
                    t.start()
                    threads.append(t)
                    if len(threads) % 20 == 0:
                        time.sleep(0.001)
                for t in threads:
                    if t.is_alive():
                        t.join(timeout=0.5)

            # 模式2: 仅 monlist
            elif config.probe_action == PROBE_ACTION_MONLIST:
                threads = []
                for ip in ips:
                    if self._stop_event.is_set():
                        break
                    t = threading.Thread(target=_worker, args=(ip, PROBE_ACTION_MONLIST), daemon=True)
                    t.start()
                    threads.append(t)
                    if len(threads) % 20 == 0:
                        time.sleep(0.001)
                for t in threads:
                    if t.is_alive():
                        t.join(timeout=0.5)

            # 模式3: 先 probe 筛选存活，再 monlist 测量
            else:  # both
                self._log("  📡 第一阶段: 存活探测 (probe)")
                probe_threads = []
                probe_results: Dict[str, ServerResult] = {}
                probe_lock = threading.Lock()

                def _probe_worker(ip: str):
                    semaphore.acquire()
                    try:
                        if self._stop_event.is_set():
                            return
                        with self._stats_lock:
                            self.stats["current_ip"] = ip
                        res = _test_probe(ip, config.ntp_port, config.timeout_sec)
                        with probe_lock:
                            probe_results[ip] = res
                        with results_lock:
                            self._all_results.append(res)
                            cnt = len(self._all_results)
                            self.stats["tested"] = cnt
                            self.stats["progress_percent"] = round(
                                cnt / max(1, self.stats["total_tasks"]) * 100, 1
                            )
                            if res.responded:
                                self.stats["responded"] = self.stats.get("responded", 0) + 1
                            else:
                                self.stats["failed"] = self.stats.get("failed", 0) + 1
                    finally:
                        semaphore.release()

                for ip in ips:
                    if self._stop_event.is_set():
                        break
                    t = threading.Thread(target=_probe_worker, args=(ip,), daemon=True)
                    t.start()
                    probe_threads.append(t)
                    if len(probe_threads) % 20 == 0:
                        time.sleep(0.001)

                for t in probe_threads:
                    if t.is_alive():
                        t.join(timeout=0.5)

                if self._stop_event.is_set():
                    self._update_stage("scanning", "stopped")
                    self._finalize_run("stopped", start_time)
                    self._log("🛑 扫描已停止。")
                    return

                alive_ips = [ip for ip, res in probe_results.items() if res.responded]
                self._log(f"  📡 存活探测完成: {len(alive_ips)}/{len(ips)} 台服务器响应")

                if alive_ips:
                    self._log(f"  📊 第二阶段: Monlist 放大率测量 ({len(alive_ips)} 台)")
                    mon_threads = []
                    for ip in alive_ips:
                        if self._stop_event.is_set():
                            break
                        t = threading.Thread(target=_worker, args=(ip, PROBE_ACTION_MONLIST), daemon=True)
                        t.start()
                        mon_threads.append(t)
                        if len(mon_threads) % 20 == 0:
                            time.sleep(0.001)

                    for t in mon_threads:
                        if t.is_alive():
                            t.join(timeout=0.5)
                else:
                    self._log("  ⚠️  没有存活的 NTP 服务器，跳过 monlist 测量")

            if self._stop_event.is_set():
                self._update_stage("scanning", "stopped")
                self._finalize_run("stopped", start_time)
                self._log("🛑 扫描已停止。")
                return

            self._update_stage("scanning", "completed")

            # Stage 3: 筛选高倍率目标
            if not self._stop_event.is_set():
                self._log("🔍 筛选高放大率优质资源 …")
                self._update_stage("filtering", "running")

                self._qualified_ips, summary = _filter_and_rank(
                    self._all_results,
                    config.min_amplification,
                    config.min_availability,
                )
                with self._stats_lock:
                    self.stats["qualified"] = len(self._qualified_ips)
                self._update_stage("filtering", "completed", qualified=len(self._qualified_ips))

                avg_amp = float(summary.get("avg_amplification", 0.0) or 0.0)
                max_amp = float(summary.get("max_amplification", 0.0) or 0.0)
                self._log(f"📊 筛选结果: {summary['responded_ips']} 个可应答 → "
                          f"{summary['qualified_count']} 个优质资源")
                self._log(f"   平均放大率: {avg_amp:.2f}x, "
                          f"最大放大率: {max_amp:.2f}x")

            if self._stop_event.is_set():
                self._update_stage("filtering", "stopped")
                self._finalize_run("stopped", start_time)
                self._log("🛑 扫描已停止。")
                return

            # Stage 4: 保存结果
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
            f.write(f"# NTP 优质反射器 IP 列表（放大率 ≥ {config.min_amplification}x）\n")
            f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
            f.write(f"# 探测动作: {config.probe_action}\n")
            for ip in self._qualified_ips:
                f.write(f"{ip}\n")

        # 完整 CSV
        csv_file = out / "scan_results.csv"
        with csv_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Action", "Responded",
                             "RequestBytes", "ResponseBytes", "Amplification",
                             "ResponsePackets", "LatencyMs", "Error"])
            for r in self._all_results:
                writer.writerow([
                    r.ip, r.action, r.responded,
                    r.request_bytes, r.response_bytes, r.amplification_factor,
                    r.response_packets, r.latency_ms, r.error,
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
    min_availability: float,
) -> tuple:
    """筛选、去重、排序（按 monlist 放大率优先）"""
    # 按 IP 聚合
    ip_data: Dict[str, Dict[str, Any]] = {}
    for r in all_results:
        entry = ip_data.setdefault(r.ip, {
            "monlist_factors": [],
            "probe_factors": [],
            "latencies": [],
            "total": 0,
            "responded": 0,
            "monlist_responded": 0,
            "response_packets": 0,
        })
        entry["total"] += 1
        if r.responded:
            entry["responded"] += 1
            entry["latencies"].append(r.latency_ms)
            if r.action == PROBE_ACTION_MONLIST:
                entry["monlist_factors"].append(r.amplification_factor)
                entry["monlist_responded"] += 1
                entry["response_packets"] += r.response_packets
            elif r.action == PROBE_ACTION_PROBE:
                entry["probe_factors"].append(r.amplification_factor)

    qualified = []
    responded_ips = 0
    for ip, data in ip_data.items():
        if data["responded"] == 0:
            continue
        responded_ips += 1
        availability = (data["responded"] / data["total"]) * 100

        # 优先使用 monlist 放大率，没有则用 probe
        if data["monlist_factors"]:
            avg_amp = statistics.mean(data["monlist_factors"])
        elif data["probe_factors"]:
            avg_amp = statistics.mean(data["probe_factors"])
        else:
            avg_amp = 0

        if avg_amp >= min_amplification and availability >= min_availability:
            avg_latency = statistics.mean(data["latencies"]) if data["latencies"] else 0
            qualified.append((avg_amp, ip, availability, avg_latency))

    # 按放大率降序
    qualified.sort(key=lambda x: x[0], reverse=True)

    all_monlist_factors = [v for d in ip_data.values() for v in d["monlist_factors"]]
    max_amp = max(all_monlist_factors) if all_monlist_factors else 0
    avg_amp_all = statistics.mean(all_monlist_factors) if all_monlist_factors else 0

    qualified_ips = [ip for _, ip, _, _ in qualified]
    summary = {
        "total_ips": len(ip_data),
        "responded_ips": responded_ips,
        "qualified_count": len(qualified),
        "qualified_ips": qualified_ips,
        "min_amplification_threshold": min_amplification,
        "min_availability_threshold": min_availability,
        "avg_amplification": round(avg_amp_all, 2),
        "max_amplification": round(max_amp, 2),
        "top_10": [
            {"ip": ip, "amplification": round(amp, 2), "availability": round(rel, 1)}
            for amp, ip, rel, _ in qualified[:10]
        ],
        "timestamp": datetime.now().isoformat(),
    }
    return qualified_ips, summary


# ── CLI 入口 ──────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="NTP 攻击资源扫描器")
    parser.add_argument("--ip-file", required=True, help="候选 NTP 服务器 IP 列表")
    parser.add_argument("--output-dir", default="./ntp_scan_output", help="输出目录")
    parser.add_argument("--action", default=DEFAULT_PROBE_ACTION,
                        choices=list(PROBE_ACTIONS.keys()),
                        help="探测动作")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--min-amp", type=float, default=DEFAULT_MIN_AMPLIFICATION)
    parser.add_argument("--min-availability", type=float, default=DEFAULT_MIN_AVAILABILITY)
    parser.add_argument("--max-ips", type=int, default=0)

    args = parser.parse_args()

    config = ScanConfig(
        ip_file=args.ip_file,
        output_dir=args.output_dir,
        probe_action=args.action,
        timeout_sec=args.timeout,
        concurrency=args.concurrency,
        min_amplification=args.min_amp,
        min_availability=args.min_availability,
        max_ips=args.max_ips,
    )

    scanner = NTPResourceScanner()

    def print_log(msg: str):
        print(msg)

    scanner.run_scan(config, log_callback=print_log)

    print("\n📊 最终统计:")
    stats = scanner.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"\n 优质资源 ({len(scanner.get_qualified_ips())} 个):")
    for ip in scanner.get_qualified_ips()[:10]:
        print(f"    {ip}")


if __name__ == "__main__":
    main()
