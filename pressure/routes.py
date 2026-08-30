"""Flask 路由注册（核心压力测试路由）。

将拆分前 ``app.py`` 第 819-1164 行内联在 app 上的路由收束到单个
``pressure_bp`` 蓝图中，保持：

* 所有 URL 路径与请求/响应格式不变
* 路由函数名保持不变，方便搜索与调试
* 全局状态通过 :class:`pressure.state.GlobalState` 注入，不再直接依赖
  模块级单例（但 ``app.py`` 仍会创建模块级 ``state = GlobalState()`` 保持
  与现有部署的兼容性）
"""

import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from flask import Blueprint, jsonify, render_template, request

from . import constants as _c
from .geoip_utils import build_geo_points
from .servers import (
    _list_server_file_sources,
    count_server_entries_in_file,
    get_default_server_file_content,
    get_effective_server_file,
    is_valid_server_method,
    list_server_source_paths,
    list_server_sources,
    read_server_entries,
    resolve_server_source,
    resolve_server_sources,
)
from .state import GlobalState

logger = logging.getLogger(__name__)


def create_pressure_blueprint(global_state: GlobalState) -> Blueprint:
    """根据给定的全局状态创建压力测试路由蓝图。

    所有路由捕获的 ``state`` 都是此函数传入的实例。
    """

    state = global_state
    bp = Blueprint("pressure", __name__)

    # ------------------------------------------------------------------
    # 页面
    # ------------------------------------------------------------------

    @bp.route("/")
    def index():
        return render_template("index.html")

    # ------------------------------------------------------------------
    # 配置与测试启停
    # ------------------------------------------------------------------

    @bp.route("/api/config", methods=["GET"])
    def get_config():
        status = state.get_status()
        status["is_data_fresh"] = status.get("victim_mbps", 0) > 0
        if (
            "expected_amplification" not in status
            or status["expected_amplification"] == 0
        ):
            if state.config:
                if state.config.method == "multi":
                    status["expected_amplification"] = 556
                elif state.config.single_method:
                    method = state.config.single_method.value
                    amp_map = {
                        "memcached": 50,
                        "dns": 54,
                        "ntp": 556,
                        "tcp": "Dynamic",
                    }
                    status["expected_amplification"] = amp_map.get(method, 10)
            else:
                status["expected_amplification"] = 10
        return jsonify(status)

    @bp.route("/api/test/start", methods=["POST"])
    def start_test():
        if state.current_test:
            return jsonify({"success": False, "message": "测试已在运行中"})
        try:
            data = request.json or {}
            if not data.get("target_ip"):
                return jsonify({"success": False, "message": "请输入目标IP"})
            multi_protocol = data.get("multi_protocol", False)
            selected_protocols = data.get("selected_protocols", [])
            protocol_sources = data.get("protocol_sources", {})

            # 解析并校验 TTL（默认 255，论文推荐）
            try:
                raw_ttl = int(data.get("ttl", 255))
            except (TypeError, ValueError):
                raw_ttl = 255
            ttl = max(1, min(255, raw_ttl))

            if multi_protocol:
                if not selected_protocols:
                    return jsonify(
                        {"success": False, "message": "请至少选择一个协议"}
                    )
                valid_protocols = ["memcached", "dns", "ntp", "tcp"]
                for protocol in selected_protocols:
                    if protocol not in valid_protocols:
                        return jsonify(
                            {
                                "success": False,
                                "message": f"无效的协议: {protocol}",
                            }
                        )
                config = _c.TestConfig(
                    target_ip=data["target_ip"],
                    target_port=int(data.get("target_port", 80)),
                    method="multi",
                    multi_protocols=selected_protocols,
                    duration_minutes=int(data.get("duration", 5)),
                    threads=int(data.get("threads", 8)),
                    data_size_kb=int(data.get("data_size_kb", 300)),
                    target_pps=int(data.get("target_pps", 5000)),
                    tcp_pkt_methods=data.get("tcp_pkt_methods", []),
                    protocol_sources=protocol_sources,
                    ttl=ttl,
                )
            else:
                if not data.get("method"):
                    return jsonify(
                        {"success": False, "message": "请选择测试方法"}
                    )
                try:
                    single_method = _c.TestMethod(data["method"])
                except ValueError:
                    return jsonify(
                        {"success": False, "message": "不支持的测试方法"}
                    )
                config = _c.TestConfig(
                    target_ip=data["target_ip"],
                    target_port=int(data.get("target_port", 80)),
                    method="single",
                    single_method=single_method,
                    multi_protocols=[data["method"]],
                    duration_minutes=int(data.get("duration", 5)),
                    threads=int(data.get("threads", 8)),
                    data_size_kb=int(data.get("data_size_kb", 300)),
                    target_pps=int(data.get("target_pps", 5000)),
                    tcp_pkt_methods=data.get("tcp_pkt_methods", []),
                    protocol_sources=data.get("protocol_sources", {}),
                    ttl=ttl,
                )
            success, message = state.start_test(config)
            return jsonify({"success": success, "message": message})
        except Exception as e:
            logger.error("启动测试错误: %s", str(e))
            return jsonify({"success": False, "message": f"启动失败: {str(e)}"})

    @bp.route("/api/test/stop", methods=["POST"])
    def stop_test():
        success, message = state.stop_test()
        return jsonify({"success": success, "message": message})

    @bp.route("/api/test/reset", methods=["POST"])
    def reset_test():
        state.reset()
        return jsonify({"success": True, "message": "已重置"})

    # ------------------------------------------------------------------
    # Servers / 协议资源管理
    # ------------------------------------------------------------------

    @bp.route("/api/servers/<method>", methods=["GET"])
    def get_servers(method):
        try:
            if not is_valid_server_method(method):
                return jsonify({"success": False, "message": "不支持的方法"}), 400
            result = list_server_sources(method)
            if result.get("total", 0) == 0:
                result["message"] = "暂无该协议的质量 IP，请先执行扫描任务"
            return jsonify(result)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    @bp.route("/api/servers/<method>/list", methods=["GET"])
    def get_server_list(method):
        if not is_valid_server_method(method):
            return jsonify({"success": False, "message": "不支持的方法"})
        source_files = resolve_server_sources(
            method, request.args.getlist("files")
        )
        servers = read_server_entries(method, source_files=source_files)
        return jsonify({"success": True, "servers": servers})

    @bp.route("/api/servers/<method>/files", methods=["GET"])
    def get_server_sources(method):
        if not is_valid_server_method(method):
            return jsonify(
                {"success": False, "message": "Unsupported method"}
            )
        return jsonify(
            {"success": True, "files": _list_server_file_sources(method)}
        )

    @bp.route("/api/servers/<method>/file", methods=["GET"])
    def get_server_file_content(method):
        if not is_valid_server_method(method):
            return jsonify(
                {"success": False, "message": "Unsupported method"}
            )
        source = request.args.get("source", "").strip()
        source_path = resolve_server_source(method, source or None)
        if source and source_path is None:
            return (
                jsonify(
                    {"success": False, "message": "Source file not found"}
                ),
                404,
            )
        if source_path is None:
            return (
                jsonify(
                    {"success": False, "message": "Source file not found"}
                ),
                404,
            )
        filename = str(source_path)
        content = get_default_server_file_content(method)
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read()
        return jsonify(
            {
                "success": True,
                "file": {
                    "name": os.path.basename(filename),
                    "path": filename,
                    "source": os.path.basename(filename),
                    "type": "text",
                    "editable": True,
                    "content": content,
                },
            }
        )

    @bp.route("/api/servers/<method>/file", methods=["POST"])
    def create_server_file(method):
        if not is_valid_server_method(method):
            return jsonify(
                {"success": False, "message": "Unsupported method"}
            )
        data = request.json or {}
        filename = data.get("filename", "").strip()
        if not filename:
            return jsonify({"success": False, "message": "请输入文件名"})
        if not filename.endswith(".txt"):
            filename = filename + ".txt"
        # 校验文件名：只允许字母、数字、下划线、横线和 .txt
        if not re.match(r"^[a-zA-Z0-9_\-]+\.txt$", filename):
            return jsonify(
                {
                    "success": False,
                    "message": "文件名只允许英文字母、数字、下划线和横线",
                }
            )
        ip_lists_dir = (
            Path(_c.ATTACK_RESOURCES_ROOT) / method / "resources" / "ip_lists"
        )
        ip_lists_dir.mkdir(parents=True, exist_ok=True)
        file_path = ip_lists_dir / filename
        if file_path.exists():
            return jsonify(
                {
                    "success": False,
                    "message": f"文件 {filename} 已存在",
                }
            )
        try:
            file_path.write_text("# 每行一个反射器IP或域名\n", encoding="utf-8")
            logger.info("已创建源文件: %s", file_path)
            return jsonify(
                {
                    "success": True,
                    "message": f"文件 {filename} 已创建",
                    "file": {
                        "name": filename,
                        "path": str(file_path),
                        "entry_count": 0,
                        "editable": True,
                    },
                }
            )
        except Exception as e:
            logger.error("创建文件失败: %s", e)
            return jsonify(
                {"success": False, "message": f"创建文件失败: {str(e)}"}
            )

    @bp.route("/api/servers/<method>/geo", methods=["GET"])
    def get_server_geo(method):
        if not is_valid_server_method(method):
            return jsonify({"success": False, "message": "不支持的方法"})
        try:
            source_files = resolve_server_sources(
                method, request.args.getlist("files")
            )
            return jsonify(
                build_geo_points(method, source_files=source_files)
            )
        except Exception as e:
            logger.error(
                "GeoIP endpoint failed: %s", e, exc_info=True
            )
            return jsonify({"success": False, "message": str(e)})

    @bp.route("/api/servers/<method>/file", methods=["PUT"])
    def update_server_file_content(method):
        if not is_valid_server_method(method):
            return jsonify(
                {"success": False, "message": "Unsupported method"}
            )
        data = request.json or {}
        content = data.get("content", "")
        if not isinstance(content, str):
            return jsonify(
                {"success": False, "message": "File content must be a string"}
            )
        source = request.args.get("source", "").strip()
        source_path = resolve_server_source(method, source or None)
        if source and source_path is None:
            return (
                jsonify(
                    {"success": False, "message": "Source file not found"}
                ),
                404,
            )
        if source_path is None:
            return (
                jsonify(
                    {"success": False, "message": "Source file not found"}
                ),
                404,
            )
        filename = str(source_path)
        normalized = content.replace("\r\n", "\n")
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(
                filename, "w", encoding="utf-8", newline="\n"
            ) as f:
                f.write(normalized)
            valid_count = len(
                [
                    line
                    for line in normalized.split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]
            )
            return jsonify(
                {
                    "success": True,
                    "message": f"Saved {valid_count} active entries",
                }
            )
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    @bp.route("/api/servers/<method>/update", methods=["POST"])
    def update_server_list(method):
        if not is_valid_server_method(method):
            return jsonify({"success": False, "message": "不支持的方法"})
        data = request.json or {}
        servers = data.get("servers", [])
        if not isinstance(servers, list):
            return jsonify(
                {"success": False, "message": "服务器列表必须是数组"}
            )
        valid = [
            s.strip()
            for s in servers
            if s.strip() and not s.strip().startswith("#")
        ]
        source = request.args.get("source", "").strip()
        filename = get_effective_server_file(method, source or None)
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("# 每行一个反射器IP或域名\n")
                for s in valid:
                    f.write(s + "\n")
            return jsonify(
                {
                    "success": True,
                    "message": f"已保存 {len(valid)} 个服务器",
                }
            )
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    @bp.route("/api/servers/count", methods=["POST"])
    def get_server_count():
        try:
            data = request.json or {}
            protocols = data.get("protocols", [])
            total_count = 0
            protocol_counts: Dict[str, int] = {}
            for protocol in protocols:
                if protocol in _c.VALID_SERVER_PROTOCOLS:
                    source_paths = list_server_source_paths(protocol)
                    count = sum(
                        count_server_entries_in_file(p) for p in source_paths
                    )
                    protocol_counts[protocol] = count
                    total_count += count
            return jsonify(
                {
                    "success": True,
                    "total_count": total_count,
                    "protocol_counts": protocol_counts,
                }
            )
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    # ------------------------------------------------------------------
    # 探测 / 系统
    # ------------------------------------------------------------------

    @bp.route("/api/ping", methods=["POST"])
    def ping_target():
        data = request.json or {}
        target = data.get("target")
        if not target:
            return jsonify({"success": False, "message": "缺少目标地址"})
        try:
            cmd = ["ping", "-c", "1", "-W", "2", target]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                match = re.search(
                    r"time=(\d+(?:\.\d+)?)\s*ms", result.stdout
                )
                if match:
                    latency = float(match.group(1))
                    return jsonify({"success": True, "latency": latency})
            return jsonify(
                {"success": False, "message": "ping超时或无法到达"}
            )
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    @bp.route("/api/tcping", methods=["POST"])
    def tcping():
        import socket
        import time as _time

        data = request.json or {}
        target = data.get("target")
        port = data.get("port", 80)
        timeout = data.get("timeout", 5)  # 默认 5 秒超时
        if not target:
            return jsonify({"success": False, "message": "缺少目标地址"})
        try:
            start = _time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            end = _time.time()
            sock.close()
            latency = (end - start) * 1000
            return jsonify(
                {"success": True, "latency": round(latency, 2)}
            )
        except socket.timeout:
            return jsonify(
                {
                    "success": False,
                    "message": f"连接超时（{timeout}秒）",
                }
            )
        except ConnectionRefusedError:
            return jsonify(
                {
                    "success": False,
                    "message": "连接被拒绝，端口可能未开放",
                }
            )
        except Exception as e:
            return jsonify(
                {"success": False, "message": f"连接失败: {str(e)}"}
            )

    @bp.route("/api/system/info", methods=["GET"])
    def get_system_info():
        try:
            # 延迟导入 psutil，使模块在未安装压力测试依赖时仍能导入
            import psutil

            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            net_io = psutil.net_io_counters()
            disk = psutil.disk_usage("/")
            return jsonify(
                {
                    "success": True,
                    "cpu_percent": cpu_percent,
                    "memory": {
                        "total": memory.total,
                        "available": memory.available,
                        "percent": memory.percent,
                        "used": memory.used,
                        "free": memory.free,
                    },
                    "network": {
                        "bytes_sent": net_io.bytes_sent,
                        "bytes_recv": net_io.bytes_recv,
                        "packets_sent": net_io.packets_sent,
                        "packets_recv": net_io.packets_recv,
                    },
                    "disk": {
                        "total": disk.total,
                        "used": disk.used,
                        "free": disk.free,
                        "percent": disk.percent,
                    },
                    "timestamp": time.time(),
                }
            )
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    # ------------------------------------------------------------------
    # 错误处理器：绑定在 bp 上用 ``app_errorhandler``，对所有请求生效
    # ------------------------------------------------------------------

    @bp.app_errorhandler(404)
    def not_found(error):
        return jsonify({"success": False, "message": "资源未找到"}), 404

    @bp.app_errorhandler(500)
    def internal_error(error):
        return (
            jsonify({"success": False, "message": "服务器内部错误"}),
            500,
        )

    return bp
