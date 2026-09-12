"""进程内任务队列调度器。

各协议（tcp / dns / ntp / memcached）独立维护并发上限与排队队列。
任务入队后由调度器在额度可用时自动启动，支持取消、排序、持久化。

用法：
    from attack_resources.shared.task_queue import queue_manager

    # 协议模块注册启动器和运行计数器（各模块初始化时调用一次）
    queue_manager.register_launcher("tcp", launch_tcp_run)
    queue_manager.register_running_counter("tcp", lambda: len(tcp_scan_registry.active_run_ids()))

    # 入队
    run_id = queue_manager.enqueue("tcp", payload_dict)

    # 任务结束时调用（worker finally 中）
    queue_manager.on_task_finished("tcp")
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_PROTO_NAMES = ("tcp", "dns", "ntp", "memcached")
_DEFAULT_MAX_CONCURRENT = {"tcp": 3, "dns": 3, "ntp": 3, "memcached": 3}

# 状态文件目录（与 api_credentials.json 同级）
_STATE_DIR = Path(__file__).resolve().parent
_STATE_FILE = _STATE_DIR / "queue_state.json"
_CONFIG_FILE = _STATE_DIR / "queue_config.json"

# recent_events 保留时长（秒）
_EVENT_TTL = 300


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_run_id(proto: str) -> str:
    """生成队列任务的 run_id（含微秒，保证唯一性）。"""
    return datetime.now().strftime(f"{proto}_%Y%m%d_%H%M%S_%f")


@dataclass
class QueuedTask:
    """排队中的任务。"""
    proto: str
    run_id: str
    payload: Dict[str, Any]
    queued_at: str


@dataclass
class QueueEvent:
    """已结束的排队任务事件（取消/启动失败），供前端短暂展示。"""
    run_id: str
    proto: str
    event_type: str          # "cancelled" | "failed_to_start"
    reason: str
    timestamp: str
    payload_summary: Dict[str, Any] = field(default_factory=dict)


class TaskQueueManager:
    """单例任务队列管理器。

    线程安全；惰性初始化（首次调用 enqueue/register 时创建）。
    """

    _instance: Optional["TaskQueueManager"] = None
    _instance_lock = Lock()

    def __new__(cls) -> "TaskQueueManager":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._lock = Lock()
        self._pending: Dict[str, List[QueuedTask]] = {p: [] for p in _PROTO_NAMES}
        self._max_concurrent: Dict[str, int] = dict(_DEFAULT_MAX_CONCURRENT)

        # launcher: proto -> fn(payload, run_id) -> bool
        self._launchers: Dict[str, Callable[[Dict[str, Any], str], bool]] = {}
        # running_counter: proto -> fn() -> int
        self._running_counters: Dict[str, Callable[[], int]] = {}

        # 最近事件（取消/启动失败），按时间戳过期清理
        self._events: List[QueueEvent] = []

        self._watcher_started = False

        # 恢复持久化状态
        self._load_config()
        self._load_state()

    # ── 持久化 ──────────────────────────────────────────

    def _load_config(self) -> None:
        try:
            if _CONFIG_FILE.exists():
                data = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
                mc = data.get("max_concurrent", {})
                for proto, val in mc.items():
                    if proto in _PROTO_NAMES and isinstance(val, int) and val >= 1:
                        self._max_concurrent[proto] = val
        except Exception as exc:
            logger.warning("读取队列配置失败: %s", exc)

    def _save_config(self) -> None:
        data = {"max_concurrent": self._max_concurrent}
        self._atomic_write(_CONFIG_FILE, data)

    def _load_state(self) -> None:
        try:
            if _STATE_FILE.exists():
                data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
                for proto in _PROTO_NAMES:
                    items = data.get("pending", {}).get(proto, [])
                    self._pending[proto] = [
                        QueuedTask(
                            proto=item["proto"],
                            run_id=item["run_id"],
                            payload=item.get("payload", {}),
                            queued_at=item.get("queued_at", _now_iso()),
                        )
                        for item in items
                    ]
                events = data.get("events", [])
                now = datetime.now(timezone.utc)
                self._events = []
                for ev in events:
                    try:
                        ev_time = datetime.fromisoformat(ev["timestamp"])
                        if (now - ev_time).total_seconds() < _EVENT_TTL:
                            self._events.append(QueueEvent(**ev))
                    except Exception:
                        pass
        except Exception as exc:
            logger.warning("读取队列状态失败: %s", exc)

    def _save_state(self) -> None:
        data = {
            "pending": {
                proto: [asdict(task) for task in tasks]
                for proto, tasks in self._pending.items()
            },
            "events": [asdict(ev) for ev in self._events],
        }
        self._atomic_write(_STATE_FILE, data)

    @staticmethod
    def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(path))

    def _prune_events(self) -> None:
        now = datetime.now(timezone.utc)
        self._events = [
            ev for ev in self._events
            if (now - datetime.fromisoformat(ev.timestamp)).total_seconds() < _EVENT_TTL
        ]

    # ── 协议注册 ──────────────────────────────────────────

    def register_launcher(self, proto: str, fn: Callable[[Dict[str, Any], str], bool]) -> None:
        with self._lock:
            self._launchers[proto] = fn

    def register_running_counter(self, proto: str, fn: Callable[[], int]) -> None:
        with self._lock:
            self._running_counters[proto] = fn

    # ── 内部辅助 ──────────────────────────────────────────

    def _running_count(self, proto: str) -> int:
        fn = self._running_counters.get(proto)
        if fn is None:
            return 0
        try:
            return fn()
        except Exception:
            return 0

    # ── 对外 API ──────────────────────────────────────────

    def enqueue(self, proto: str, payload: Dict[str, Any]) -> str:
        """入队一个任务，返回 run_id。"""
        run_id = _generate_run_id(proto)
        task = QueuedTask(
            proto=proto,
            run_id=run_id,
            payload=payload,
            queued_at=_now_iso(),
        )
        with self._lock:
            self._pending[proto].append(task)
            self._save_state()
        logger.info("任务入队 %s: %s", proto, run_id)
        self.try_dispatch(proto)
        return run_id

    def try_dispatch(self, proto: str) -> None:
        """尝试为指定协议调度排队任务。"""
        with self._lock:
            launcher = self._launchers.get(proto)
            if launcher is None:
                return
            max_c = self._max_concurrent.get(proto, 1)
            while self._pending[proto] and self._running_count(proto) < max_c:
                task = self._pending[proto].pop(0)
                success = False
                failure_reason = ""
                try:
                    success = launcher(task.payload, task.run_id)
                    if not success:
                        failure_reason = "启动器返回失败"
                except Exception as exc:
                    failure_reason = str(exc)
                    logger.exception("任务启动异常 %s: %s", proto, task.run_id)

                if success:
                    logger.info("任务已启动 %s: %s", proto, task.run_id)
                else:
                    logger.warning("任务启动失败 %s: %s — %s", proto, task.run_id, failure_reason)
                    self._events.append(QueueEvent(
                        run_id=task.run_id,
                        proto=proto,
                        event_type="failed_to_start",
                        reason=failure_reason,
                        timestamp=_now_iso(),
                        payload_summary=self._summarize_payload(task.payload),
                    ))
                    self._prune_events()
                    self._save_state()
                    # 继续循环尝试下一个任务

    def on_task_finished(self, proto: str) -> None:
        """任务结束钩子（worker 线程 finally 中调用）。"""
        self.try_dispatch(proto)

    def cancel(self, proto: str, run_id: str) -> bool:
        """取消排队中的任务，返回是否成功。"""
        with self._lock:
            tasks = self._pending.get(proto, [])
            for i, task in enumerate(tasks):
                if task.run_id == run_id:
                    tasks.pop(i)
                    self._events.append(QueueEvent(
                        run_id=run_id,
                        proto=proto,
                        event_type="cancelled",
                        reason="用户取消",
                        timestamp=_now_iso(),
                        payload_summary=self._summarize_payload(task.payload),
                    ))
                    self._prune_events()
                    self._save_state()
                    logger.info("任务已取消 %s: %s", proto, run_id)
                    return True
            return False

    def move(self, proto: str, run_id: str, direction: str) -> bool:
        """上移/下移排队任务，返回是否成功。"""
        with self._lock:
            tasks = self._pending.get(proto, [])
            idx = None
            for i, task in enumerate(tasks):
                if task.run_id == run_id:
                    idx = i
                    break
            if idx is None:
                return False
            if direction == "up" and idx > 0:
                tasks[idx], tasks[idx - 1] = tasks[idx - 1], tasks[idx]
                self._save_state()
                return True
            if direction == "down" and idx < len(tasks) - 1:
                tasks[idx], tasks[idx + 1] = tasks[idx + 1], tasks[idx]
                self._save_state()
                return True
            return False

    def get_queue(self, proto: str) -> List[Dict[str, Any]]:
        """返回指定协议的排队任务列表（含位置编号）。"""
        with self._lock:
            tasks = self._pending.get(proto, [])
            return [
                {
                    "run_id": task.run_id,
                    "queued_at": task.queued_at,
                    "queue_position": i + 1,
                    "payload": task.payload,
                    "payload_summary": self._summarize_payload(task.payload),
                    "status": "queued",
                }
                for i, task in enumerate(tasks)
            ]

    def get_events(self, proto: Optional[str] = None) -> List[Dict[str, Any]]:
        """返回最近事件（取消/启动失败），可按协议过滤。"""
        with self._lock:
            self._prune_events()
            events = self._events
            if proto:
                events = [ev for ev in events if ev.proto == proto]
            return [asdict(ev) for ev in events]

    def get_config(self) -> Dict[str, Any]:
        """返回各协议并发上限 + 当前运行数 + 排队数。"""
        with self._lock:
            result: Dict[str, Any] = {}
            for proto in _PROTO_NAMES:
                result[proto] = {
                    "max_concurrent": self._max_concurrent.get(proto, 1),
                    "running": self._running_count(proto),
                    "queued": len(self._pending.get(proto, [])),
                }
            return result

    def update_config(self, new_limits: Dict[str, int]) -> Dict[str, Any]:
        """更新并发上限（部分字段可省略），触发全协议调度。"""
        with self._lock:
            for proto, val in new_limits.items():
                if proto in _PROTO_NAMES and isinstance(val, int) and val >= 1:
                    self._max_concurrent[proto] = val
            self._save_config()
        # 更新后触发全协议调度（调大上限时排队任务立即补位）
        for proto in _PROTO_NAMES:
            self.try_dispatch(proto)
        return self.get_config()

    def start_watcher(self) -> None:
        """启动兜底 watcher 线程（daemon，每 10s 调度所有协议）。"""
        if self._watcher_started:
            return
        self._watcher_started = True

        def _watch():
            while True:
                for proto in _PROTO_NAMES:
                    try:
                        self.try_dispatch(proto)
                    except Exception:
                        pass
                threading.Event().wait(10.0)

        t = Thread(target=_watch, daemon=True, name="queue-watcher")
        t.start()
        logger.info("队列 watcher 已启动")

    @staticmethod
    def _summarize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        """提取 payload 中的关键摘要字段供前端展示。"""
        summary: Dict[str, Any] = {}
        for key in ("ip_file", "pkt_method", "pkt_methods", "target_host",
                     "query_type", "probe_action", "concurrency", "dry_run"):
            if key in payload:
                summary[key] = payload[key]
        return summary


# 模块级单例
queue_manager = TaskQueueManager()
