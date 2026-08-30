"""应用启动引导：创建 Flask 实例、注册蓝图、构造全局状态。

拆分前位于 ``app.py`` 的 102-120、183-187、1167-1290 行。入口 ``app.py`` 保持极薄
的转发层，所有“真正做事情”的逻辑收敛到此模块。
"""

import logging
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Tuple

from flask import Flask
from flask_session import Session

from . import constants as _c
from .routes import create_pressure_blueprint
from .state import GlobalState

logger = logging.getLogger(__name__)


def register_protocol_blueprints(app: Flask) -> None:
    """注册各协议模块的 Flask 蓝图（蓝图来自 attack_resources 子模块）。"""
    # 延迟导入，避免 pressure 包被扫描模块反向引用
    from attack_resources.shared.attack_resource_api import attack_resource_bp
    from attack_resources.shared.file_system_api import file_system_bp
    from attack_resources.tcp.code.routes import tcp_censor_bp
    from attack_resources.dns.code.routes import dns_scan_bp
    from attack_resources.memcached.code.routes import memcached_scan_bp
    from attack_resources.ntp.code.routes import ntp_scan_bp

    app.register_blueprint(tcp_censor_bp)
    app.register_blueprint(dns_scan_bp)
    app.register_blueprint(memcached_scan_bp)
    app.register_blueprint(ntp_scan_bp)
    app.register_blueprint(attack_resource_bp)
    app.register_blueprint(file_system_bp)


def _configure_logging_basic() -> None:
    """模块级基础日志配置（仅在进程启动时调用一次）。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def create_testers() -> dict:
    """构造协议测试器与多协议联合测试器实例字典。

    拆分到独立函数是为了便于测试时替换为 mock 对象。
    """
    from attack_resources.memcached.code.tester import MemcachedTester
    from attack_resources.dns.code.tester import DNSTester
    from attack_resources.ntp.code.tester import NTPTester
    from attack_resources.tcp.code.tester import TcpTester
    from multi_protocol_test import MultiProtocolTester

    return {
        "testers": {
            "memcached": MemcachedTester(),
            "dns": DNSTester(),
            "ntp": NTPTester(),
            "tcp": TcpTester(),
        },
        "multi_tester": MultiProtocolTester(),
    }


DEFAULT_SECRET_KEY = "your-secret-key-here-change-in-production"


def create_app(
    secret_key: str | None = None,
    testers_and_multi: dict | None = None,
) -> Tuple[Flask, GlobalState]:
    """构造 Flask 应用与全局运行期状态。

    参数
    ----
    secret_key:
        Flask 的 session 密钥；未指定时依次取环境变量 ``PRESSURE_SECRET_KEY``
        与开发用默认值。生产环境务必通过环境变量设置。
    testers_and_multi:
        可选，包含 ``testers`` 和 ``multi_tester`` 的字典，供测试注入 mock。
    """
    _configure_logging_basic()

    # 模板与静态文件位于仓库根（templates/、static/），不在 pressure/ 包内；
    # __init__.py 所在目录向上一级即项目根
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent.parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent.parent / "static"),
    )
    app.secret_key = (
        secret_key
        or os.environ.get("PRESSURE_SECRET_KEY")
        or DEFAULT_SECRET_KEY
    )
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_USE_SIGNER"] = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    Session(app)

    t = testers_and_multi if testers_and_multi is not None else create_testers()
    state = GlobalState(
        tester_factory=t.get("testers"),
        multi_tester=t.get("multi_tester"),
    )

    app.register_blueprint(create_pressure_blueprint(state))
    register_protocol_blueprints(app)

    # 暴露 state 到 app.extensions，便于测试或蓝图内需要时访问
    app.extensions["pressure_state"] = state

    return app, state


# ---------------------------------------------------------------------------
# CLI 启动辅助
# ---------------------------------------------------------------------------


def check_root_privileges() -> bool:
    # Linux-only：os.geteuid 只存在于 POSIX
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        # 非 POSIX（如 Windows）：无法通过 uid 判断，默认放行
        return True
    if geteuid() != 0:
        print("⚠️  警告: 某些功能需要root权限才能正常运行")
        print("💡 建议使用: sudo python3 app.py")
        return False
    return True


def migrate_server_files() -> None:
    """将旧格式 servers.txt 迁移至 ip_lists/default.txt"""
    for protocol in _c.VALID_SERVER_PROTOCOLS:
        ip_lists_dir = (
            Path(_c.ATTACK_RESOURCES_ROOT)
            / protocol
            / "resources"
            / "ip_lists"
        )
        ip_lists_dir.mkdir(parents=True, exist_ok=True)
        old_file = (
            Path(_c.ATTACK_RESOURCES_ROOT)
            / protocol
            / "resources"
            / "servers.txt"
        )
        new_file = ip_lists_dir / "default.txt"
        if old_file.exists() and not new_file.exists():
            content = old_file.read_text(encoding="utf-8")
            new_file.write_text(content, encoding="utf-8")
            logger.info(
                "已迁移 %s 服务器列表: %s -> %s",
                protocol,
                old_file,
                new_file,
            )
        elif not old_file.exists() and not new_file.exists():
            new_file.write_text(
                "# 每行一个反射器IP或域名\n", encoding="utf-8"
            )


def create_required_directories() -> None:
    ARR = _c.ATTACK_RESOURCES_ROOT
    dirs = [
        ARR,
        os.path.join(ARR, "tcp", "code"),
        os.path.join(ARR, "tcp", "resources"),
        os.path.join(ARR, "tcp", "resources", "ip_lists"),
        os.path.join(ARR, "tcp", "config"),
        os.path.join(ARR, "tcp", "runs"),
        os.path.join(ARR, "memcached", "code"),
        os.path.join(ARR, "memcached", "resources"),
        os.path.join(ARR, "memcached", "resources", "ip_lists"),
        os.path.join(ARR, "memcached", "config"),
        os.path.join(ARR, "memcached", "runs"),
        os.path.join(ARR, "dns", "code"),
        os.path.join(ARR, "dns", "resources"),
        os.path.join(ARR, "dns", "resources", "ip_lists"),
        os.path.join(ARR, "dns", "config"),
        os.path.join(ARR, "dns", "runs"),
        os.path.join(ARR, "ntp", "code"),
        os.path.join(ARR, "ntp", "resources"),
        os.path.join(ARR, "ntp", "resources", "ip_lists"),
        os.path.join(ARR, "ntp", "config"),
        os.path.join(ARR, "ntp", "runs"),
        os.path.join(ARR, "shared", "ip_lists"),
        "static",
        "templates",
        "logs",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"📁 确保目录存在: {d}")


def create_default_server_files() -> None:
    defaults = {
        "memcached.txt": ["# Memcached服务器列表", "127.0.0.1"],
        "dns.txt": [
            "# DNS服务器列表",
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "8.8.4.4",
        ],
        "ntp.txt": [
            "# NTP服务器列表",
            "pool.ntp.org",
            "time.google.com",
            "time.windows.com",
            "time.apple.com",
        ],
    }
    for filename, lines in defaults.items():
        protocol = filename.replace(".txt", "")
        path = os.path.join(
            _c.ATTACK_RESOURCES_ROOT,
            protocol,
            "resources",
            "ip_lists",
            "default.txt",
        )
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            print(
                f"📄 创建默认服务器文件: {protocol}/ip_lists/default.txt"
            )


def setup_logging() -> None:
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = f'{log_dir}/pressure_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logging.getLogger().addHandler(file_handler)
    print(f"📝 日志文件: {log_file}")


def print_banner() -> None:
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                多协议联合压力测试系统 v4.0                   ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_help() -> None:
    help_text = """
使用方法:
  1. 启动服务器: sudo python3 app.py
  2. 打开浏览器访问: http://localhost:5000
  3. 配置测试参数并开始测试

支持协议:
  - Memcached反射攻击 (放大倍数: 10-50x)
  - DNS反射攻击 (放大倍数: 28-54x)
  - NTP反射攻击 (放大倍数: 556x)

注意事项:
  - 仅用于授权的压力测试
  - 需要root权限
"""
    print(help_text)


def run_development_server(app: Flask, host: str = "0.0.0.0", port: int = 5000) -> None:
    print("\n🚀 启动压力测试Web界面...")
    print("🌐 访问地址: http://localhost:5000")
    print("=" * 60)
    try:
        app.run(
            host=host,
            port=port,
            debug=False,
            threaded=True,
            use_reloader=False,
        )
    except KeyboardInterrupt:
        print("\n🛑 服务器被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 启动服务器失败: {str(e)}")
        traceback.print_exc()
        sys.exit(1)


def run_startup_routines() -> None:
    """执行 app.py 原有的启动期例行步骤。"""
    print_banner()
    check_root_privileges()
    create_required_directories()
    create_default_server_files()
    migrate_server_files()
    setup_logging()
    print_help()
