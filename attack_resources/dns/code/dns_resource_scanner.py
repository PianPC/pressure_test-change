#!/usr/bin/env python3
"""
DNS 攻击资源扫描器 — 基于放大率测量的优质 DNS 反射器发现工具

核心逻辑（源自 temp/dns 下的手动测试脚本）：
  1. 加载候选 DNS 服务器 IP 列表
  2. 对每台服务器发送 TXT+DNSSEC 查询（ripe.net 等大应答域名）
  3. 计算 放大率 = 响应字节数 / 请求字节数
  4. 按放大率阈值、可靠性阈值过滤，产出"优质攻击资源"
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
DEFAULT_TEST_DOMAINS = [
    "ripe.net",        # RIPE NCC ← 大量 TXT + DNSSEC，应答通常很大
    "isc.org",         # Internet Systems Consortium
    "dns-oarc.net",    # DNS OARC
    "iana.org",
    "arin.net",
    "apnic.net",
]

DNS_TYPE_MAP = {
    "TXT":    16,
    "ANY":    255,
    "DNSKEY": 48,
    "RRSIG":  46,
    "A":      1,
    "AAAA":   28,
    "MX":     15,
    "NS":     2,
    "SOA":    6,
}

DEFAULT_QUERY_TYPE = "TXT"
DEFAULT_USE_DNSSEC = True
DEFAULT_TIMEOUT_SEC = 3.0
DEFAULT_CONCURRENCY = 80
DEFAULT_MIN_AMPLIFICATION = 3.0     # 低于此倍数的直接丢弃
DEFAULT_MIN_RELIABILITY = 50.0      # 应答成功率低于此值的丢弃


# ── 数据类 ────────────────────────────────────────────

@dataclass
class ServerResult:
    ip: str
    domain: str
    query_type: str
    use_dnssec: bool
    responded: bool
    request_bytes: int = 0
    response_bytes: int = 0
    amplification_factor: float = 0.0
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class ScanConfig:
    """一次资源扫描的配置"""
    ip_file: str = ""                              # 输入 IP 列表文件
    output_dir: str = ""                           # 结果输出目录
    test_domains: List[str] = field(default_factory=lambda: DEFAULT_TEST_DOMAINS.copy())
    query_type: str = DEFAULT_QUERY_TYPE
    use_dnssec: bool = DEFAULT_USE_DNSSEC
    timeout_sec: float = DEFAULT_TIMEOUT_SEC
    concurrency: int = DEFAULT_CONCURRENCY
    min_amplification: float = DEFAULT_MIN_AMPLIFICATION
    min_reliability: float = DEFAULT_MIN_RELIABILITY
    max_ips: int = 0                               # 0 = 不限制


# ── 工具函数 ──────────────────────────────────────────

def _build_txt_dnssec_query(domain: str = "ripe.net") -> bytes:
    """构建 TXT + DNSSEC (DO=1) 查询包，与 temp/dns 中的逻辑一致"""
    transaction_id = random.randint(0, 65535)
    flags = 0x0100          # 标准查询, RD=1
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 1      # OPT 伪记录

    header = struct.pack("!HHHHHH",
                         transaction_id, flags, questions,
                         answer_rrs, authority_rrs, additional_rrs)

    # 域名编码
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part)) + part.encode()
    qname += b"\x00"
    qtype = struct.pack("!H", 16)   # TXT
    qclass = struct.pack("!H", 1)   # IN

    # OPT (EDNS0, DNSSEC OK)
    opt_name = b"\x00"
    opt_type = struct.pack("!H", 41)
    udp_payload = struct.pack("!H", 4096)
    ext_rcode = 0
    edns_ver = 0
    z = 0x8000   # DO bit
    opt_rdlen = struct.pack("!H", 0)

    opt = (opt_name + opt_type + udp_payload +
           struct.pack("!B", ext_rcode) +
           struct.pack("!B", edns_ver) +
           struct.pack("!H", z) + opt_rdlen)

    return header + qname + qtype + qclass + opt


def _build_dns_query(domain: str, qtype_val: int, use_dnssec: bool) -> bytes:
    """通用 DNS 查询包构建"""
    transaction_id = random.randint(0, 65535)
    flags = 0x0100
    questions = 1
    additional_rrs = 1 if use_dnssec else 0

    header = struct.pack("!HHHHHH",
                         transaction_id, flags, questions,
                         0, 0, additional_rrs)

    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part)) + part.encode()
    qname += b"\x00"
    qtype_bytes = struct.pack("!H", qtype_val)
    qclass_bytes = struct.pack("!H", 1)

    body = qname + qtype_bytes + qclass_bytes

    if use_dnssec:
        opt = (b"\x00" +
               struct.pack("!H", 41) +
               struct.pack("!H", 4096) +
               struct.pack("!B", 0) +
               struct.pack("!B", 0) +
               struct.pack("!H", 0x8000) +
               struct.pack("!H", 0))
        body += opt

    return header + body


# ── 单 IP 测试 ────────────────────────────────────────

def _test_single_server(
    ip: str,
    domain: str,
    qtype_val: int,
    use_dnssec: bool,
    timeout: float,
    query_data: bytes,
    query_size: int,
) -> ServerResult:
    """对单个 DNS 服务器做一轮测试，返回 ServerResult"""
    result = ServerResult(
        ip=ip,
        domain=domain,
        query_type=DNS_TYPE_MAP.get(DNS_TYPE_MAP, "TXT") if isinstance(qtype_val, str) else "TXT",
        use_dnssec=use_dnssec,
        responded=False,
    )
    # 修正 query_type 名称
    for name, val in DNS_TYPE_MAP.items():
        if val == qtype_val:
            result.query_type = name
            break

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.time()
        sock.sendto(query_data, (ip, 53))
        data, _ = sock.recvfrom(65535)
        end = time.time()
        sock.close()

        resp_size = len(data)
        if resp_size > 12:  # 起码有 DNS header
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


# ── DNS 资源扫描器 ────────────────────────────────────

class DNSResourceScanner:
    """DNS 攻击资源扫描器 —— 多域名 / 多 IP 放大率测量流水线"""

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
            "qualified": 0,            # 超过阈值的
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
                "query_type": config.query_type,
                "use_dnssec": config.use_dnssec,
                "timeout_sec": config.timeout_sec,
                "concurrency": config.concurrency,
                "min_amplification": config.min_amplification,
                "min_reliability": config.min_reliability,
                "max_ips": config.max_ips,
                "test_domains": list(config.test_domains),
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
            total_tasks = len(ips) * max(1, len(config.test_domains))
            with self._stats_lock:
                self.stats["total_ips"] = len(ips)
                self.stats["total_tasks"] = total_tasks
            self._update_stage("loading", "completed", total_ips=len(ips))
            self._update_stage("scanning", "running")
            self._log(f"✅ 加载 {len(ips)} 个候选 IP，开始放大率测量 …")

            # Stage 2: 扫描
            qtype_val = DNS_TYPE_MAP.get(config.query_type.upper(), 16)
            semaphore = threading.Semaphore(config.concurrency)
            threads: List[threading.Thread] = []
            results_lock = threading.Lock()

            for domain in config.test_domains:
                if self._stop_event.is_set():
                    break
                self._log(f"  🎯 域名: {domain} (类型: {config.query_type}{'+DNSSEC' if config.use_dnssec else ''})")

                query_data = _build_dns_query(domain, qtype_val, config.use_dnssec)
                query_size = len(query_data)

                def _worker(ip: str):
                    semaphore.acquire()
                    try:
                        if self._stop_event.is_set():
                            return
                        with self._stats_lock:
                            self.stats["current_ip"] = ip
                        res = _test_single_server(
                            ip, domain, qtype_val, config.use_dnssec,
                            config.timeout_sec, query_data, query_size,
                        )
                        with results_lock:
                            self._all_results.append(res)
                            cnt = len(self._all_results)
                            self.stats["tested"] = cnt
                            self.stats["progress_percent"] = round(cnt / max(1, self.stats["total_tasks"]) * 100, 1)
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

                avg_amp = float(summary.get("avg_amplification", summary.get("avg_amp", 0.0)) or 0.0)
                max_amp = float(summary.get("max_amplification", summary.get("max_amp", 0.0)) or 0.0)
                self._log(f"📊 筛选结果: {summary['responded_ips']} 个可应答 → "
                          f"{summary['qualified_count']} 个优质资源")
                self._log(f"   平均放大率: {avg_amp:.2f}x, "
                          f"最大放大率: {max_amp:.2f}x")

            if self._stop_event.is_set():
                self._update_stage("filtering", "stopped")
                self._finalize_run("stopped", start_time)
                self._log("🛑 扫描已停止。")
                return

            # Stage 4: 保存
            self._update_stage("saving", "running")
            if not self._stop_event.is_set() and self._qualified_ips:
                self._save_results(config, summary)
                self._log(f"💾 优质 IP 列表已保存至 {config.output_dir}")
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
            f.write(f"# DNS 优质反射器 IP 列表（放大率 ≥ {config.min_amplification}x）\n")
            f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
            for ip in self._qualified_ips:
                f.write(f"{ip}\n")

        # 完整 CSV
        csv_file = out / "scan_results.csv"
        with csv_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Domain", "QueryType", "DNSSEC", "Responded",
                             "RequestBytes", "ResponseBytes", "Amplification",
                             "LatencyMs", "Error"])
            for r in self._all_results:
                writer.writerow([
                    r.ip, r.domain, r.query_type, r.use_dnssec, r.responded,
                    r.request_bytes, r.response_bytes, r.amplification_factor,
                    r.latency_ms, r.error,
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
    # 按 IP 聚合
    ip_data: Dict[str, Dict[str, Any]] = {}
    for r in all_results:
        entry = ip_data.setdefault(r.ip, {
            "factors": [],
            "latencies": [],
            "total": 0,
            "responded": 0,
        })
        entry["total"] += 1
        if r.responded:
            entry["responded"] += 1
            entry["factors"].append(r.amplification_factor)
            entry["latencies"].append(r.latency_ms)

    qualified = []
    responded_ips = 0
    for ip, data in ip_data.items():
        if data["responded"] == 0:
            continue
        responded_ips += 1
        reliability = (data["responded"] / data["total"]) * 100
        avg_amp = statistics.mean(data["factors"]) if data["factors"] else 0
        if avg_amp >= min_amplification and reliability >= min_reliability:
            qualified.append((avg_amp, ip, reliability, statistics.mean(data["latencies"]) if data["latencies"] else 0))

    # 按放大率降序
    qualified.sort(key=lambda x: x[0], reverse=True)

    all_factors = [v for d in ip_data.values() for v in d["factors"]]
    max_amp = max(all_factors) if all_factors else 0
    avg_amp_all = statistics.mean(all_factors) if all_factors else 0

    qualified_ips = [ip for _, ip, _, _ in qualified]
    summary = {
        "total_ips": len(ip_data),
        "responded_ips": responded_ips,
        "qualified_count": len(qualified),
        "qualified_ips": qualified_ips,
        "min_amplification_threshold": min_amplification,
        "min_reliability_threshold": min_reliability,
        "avg_amplification": round(avg_amp_all, 2),
        "max_amplification": round(max_amp, 2),
        "top_10": [
            {"ip": ip, "amplification": round(amp, 2), "reliability": round(rel, 1)}
            for amp, ip, rel, _ in qualified[:10]
        ],
        "timestamp": datetime.now().isoformat(),
    }
    return qualified_ips, summary


# ── CLI 入口 ──────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="DNS 攻击资源扫描器")
    parser.add_argument("--ip-file", required=True, help="候选 DNS 服务器 IP 列表")
    parser.add_argument("--output-dir", default="./dns_scan_output", help="输出目录")
    parser.add_argument("--query-type", default="TXT", choices=list(DNS_TYPE_MAP.keys()))
    parser.add_argument("--no-dnssec", action="store_true")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--concurrency", type=int, default=80)
    parser.add_argument("--min-amp", type=float, default=3.0)
    parser.add_argument("--min-reliability", type=float, default=50.0)
    parser.add_argument("--max-ips", type=int, default=0)

    args = parser.parse_args()

    config = ScanConfig(
        ip_file=args.ip_file,
        output_dir=args.output_dir,
        query_type=args.query_type,
        use_dnssec=not args.no_dnssec,
        timeout_sec=args.timeout,
        concurrency=args.concurrency,
        min_amplification=args.min_amp,
        min_reliability=args.min_reliability,
        max_ips=args.max_ips,
    )

    scanner = DNSResourceScanner()

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
