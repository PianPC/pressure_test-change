"""全局测试状态（TestStats/GlobalState）。

这部分逻辑在拆分前位于 ``app.py`` 第 189-390 行，负责承载一次压力测试从
启动、回调更新、到结束的全部状态与协议分发逻辑。为避免循环依赖，状态模块
只 ``from .constants import ...``，不引入路由或 GeoIP 模块。
"""

import logging
import time
import traceback
from dataclasses import asdict
from threading import Lock, Thread
from typing import Any, Dict, Optional, Tuple

from .constants import (
    TestConfig,
    TestStats,
    TestStatus,
    TestMethod,
)

logger = logging.getLogger(__name__)


class GlobalState:
    """压力测试运行期的全局状态容器。

    通过 ``lock`` 保护 ``config``/``stats``/``current_test`` 等字段，保证来自
    Flask 请求线程与协议 tester 回调线程的读写一致性。
    """

    def __init__(
        self,
        tester_factory: Optional[Dict[str, Any]] = None,
        multi_tester: Optional[Any] = None,
    ):
        self.current_test = None
        self.test_thread = None
        self.config: Optional[TestConfig] = None
        self.stats = TestStats()
        self.lock = Lock()
        # 允许调用方注入 tester（便于测试隔离）；None 时由调用方稍后设置
        self.testers: Dict[str, Any] = tester_factory or {}
        self.multi_tester = multi_tester
        self.active_tester: Any = None

    # ---- 对外 API ------------------------------------------------------

    def reset(self) -> None:
        with self.lock:
            if self.current_test and self.stats.status == TestStatus.RUNNING:
                if self.config and self.config.method == "multi":
                    if self.multi_tester:
                        self.multi_tester.stop_test()
                elif self.active_tester:
                    self.active_tester.stop_test()
                time.sleep(0.5)
            self.current_test = None
            self.test_thread = None
            self.config = None
            self.stats = TestStats()
            self.active_tester = None
            logger.info("系统状态已重置")

    def start_test(self, config: TestConfig) -> Tuple[bool, str]:
        with self.lock:
            if self.current_test:
                return False, "测试已在运行中"
            self.config = config
            self.stats = TestStats()
            self.stats.status = TestStatus.RUNNING
            self.stats.start_time = time.time()
            self.stats.end_time = self.stats.start_time + (
                config.duration_minutes * 60
            )
            self.stats.selected_protocols = (
                config.multi_protocols
                if config.method == "multi"
                else [config.single_method.value]
            )
            self.current_test = config.method
            self.test_thread = Thread(target=self._run_test, daemon=True)
            self.test_thread.start()
            return True, "测试已启动"

    def stop_test(self) -> Tuple[bool, str]:
        with self.lock:
            if self.current_test and self.stats.status == TestStatus.RUNNING:
                self.stats.status = TestStatus.STOPPING
                if self.config.method == "multi":
                    if self.multi_tester:
                        self.multi_tester.stop_test()
                else:
                    if self.active_tester and hasattr(
                        self.active_tester, "stop_test"
                    ):
                        self.active_tester.stop_test()
                return True, "正在停止测试..."
            return False, "没有正在运行的测试"

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            stats_dict = asdict(self.stats)
            stats_dict["status"] = self.stats.status.value
            if self.config:
                stats_dict["config"] = {
                    "target_ip": self.config.target_ip,
                    "target_port": self.config.target_port,
                    "method": self.config.method,
                    "single_method": (
                        self.config.single_method.value
                        if self.config.single_method
                        else None
                    ),
                    "multi_protocols": self.config.multi_protocols,
                    "duration_minutes": self.config.duration_minutes,
                    "threads": self.config.threads,
                    "target_pps": self.config.target_pps,
                }
            else:
                stats_dict["config"] = None
            if (
                self.stats.status == TestStatus.RUNNING
                and self.stats.start_time
                and self.config
            ):
                elapsed = time.time() - self.stats.start_time
                total = self.config.duration_minutes * 60
                if total > 0:
                    self.stats.progress_percent = min(
                        100, (elapsed / total) * 100
                    )
                    stats_dict["progress_percent"] = (
                        self.stats.progress_percent
                    )
            return stats_dict

    # ---- 内部实现 ------------------------------------------------------

    def _run_test(self) -> None:
        try:
            config = self.config
            if config.method == "multi":
                self._run_multi(config)
            else:
                self._run_single(config)
            with self.lock:
                # STOPPING 与正常结束都落到 COMPLETED，与前端状态机保持一致
                if self.stats.status == TestStatus.STOPPING:
                    self.stats.status = TestStatus.COMPLETED
                else:
                    self.stats.status = TestStatus.COMPLETED
        except Exception as e:  # pragma: no cover - 已通过日志落盘
            logger.error(
                "测试执行错误: %s\n%s", str(e), traceback.format_exc()
            )
            self._set_error(f"测试执行错误: {str(e)}")
        finally:
            with self.lock:
                self.active_tester = None

    def _run_multi(self, config: TestConfig) -> None:
        logger.info("开始多协议联合测试，协议: %s", config.multi_protocols)

        def update_callback(stats):
            with self.lock:
                self._update_multi_stats(stats)

        self.multi_tester.run_test(
            target_ip=config.target_ip,
            target_port=config.target_port,
            duration_minutes=config.duration_minutes,
            total_threads=config.threads,
            total_target_pps=config.target_pps,
            protocols=config.multi_protocols,
            stats_callback=update_callback,
            protocol_sources=config.protocol_sources,
        )

    def _run_single(self, config: TestConfig) -> None:
        if not config.single_method:
            self._set_error("未指定测试方法")
            return
        tester = self.testers.get(config.single_method.value)
        if not tester:
            self._set_error(f"不支持的方法: {config.single_method}")
            return
        self.active_tester = tester

        def update_callback(stats):
            with self.lock:
                self._update_single_stats(stats, config.single_method.value)

        source_files = (config.protocol_sources or {}).get(
            config.single_method.value, None
        )
        test_kwargs = dict(
            target_ip=config.target_ip,
            target_port=config.target_port,
            duration_minutes=config.duration_minutes,
            threads=config.threads,
            data_size_kb=config.data_size_kb,
            target_pps=config.target_pps,
            spoof_source_ip=config.target_ip,
            spoof_source_port=config.target_port,
            stats_callback=update_callback,
        )
        if config.single_method.value in ("memcached", "dns", "ntp"):
            test_kwargs["source_files"] = source_files
        elif config.single_method.value == "tcp":
            test_kwargs["tcp_pkt_methods"] = config.tcp_pkt_methods
            test_kwargs["ttl"] = config.ttl
            test_kwargs["source_files"] = source_files
        tester.run_test(**test_kwargs)

    def _update_single_stats(self, stats: Dict[str, Any], protocol: str) -> None:
        self.stats.packets_sent = stats.get("packets_sent", 0)
        self.stats.packets_received = stats.get("packets_received", 0)
        self.stats.bytes_sent = stats.get("bytes_sent", 0)
        self.stats.bytes_received = stats.get("bytes_received", 0)
        self.stats.current_pps = stats.get("current_pps", 0)
        self.stats.current_mbps = stats.get("current_mbps", 0)
        if "victim_mbps" in stats:
            self.stats.victim_mbps = stats["victim_mbps"]
        if "max_amplification_factor" in stats:
            self.stats.max_amplification_factor = stats[
                "max_amplification_factor"
            ]
        if "expected_amplification" in stats:
            self.stats.expected_amplification = stats["expected_amplification"]
        if "progress_percent" in stats:
            self.stats.progress_percent = stats["progress_percent"]
        self.stats.protocol_details = {
            protocol: {
                "packets_sent": stats.get("packets_sent", 0),
                "current_pps": stats.get("current_pps", 0),
                "current_mbps": stats.get("current_mbps", 0),
                "amplification_factor": stats.get(
                    "max_amplification_factor", 0
                ),
            }
        }

    def _update_multi_stats(self, stats: Dict[str, Any]) -> None:
        self.stats.packets_sent = stats.get("packets_sent", 0)
        self.stats.bytes_sent = stats.get("bytes_sent", 0)
        self.stats.current_pps = stats.get("current_pps", 0)
        self.stats.current_mbps = stats.get("current_mbps", 0)
        self.stats.victim_mbps = stats.get("victim_mbps", 0.0)
        self.stats.max_amplification_factor = stats.get(
            "max_amplification_factor", 0.0
        )
        self.stats.progress_percent = stats.get("progress_percent", 0)
        if "protocol_stats" in stats:
            self.stats.protocol_details = stats["protocol_stats"]
        else:
            if not isinstance(self.stats.protocol_details, dict):
                self.stats.protocol_details = {}
        if self.config and self.config.method == "multi":
            for proto in self.config.multi_protocols:
                if proto not in self.stats.protocol_details:
                    self.stats.protocol_details[proto] = {
                        "packets_sent": 0,
                        "current_pps": 0,
                        "current_mbps": 0,
                        "amplification_factor": 0,
                    }
        if "selected_protocols" in stats:
            self.stats.selected_protocols = stats["selected_protocols"]
        elif self.config and self.config.method == "multi":
            self.stats.selected_protocols = self.config.multi_protocols

    def _set_error(self, message: str) -> None:
        with self.lock:
            self.stats.status = TestStatus.ERROR
            self.stats.error_message = message
