"""压力测试核心包。

该包从 ``app.py`` 拆分而来，保持以下对外契约不变：

- Flask 应用的路由路径与响应格式
- 蓝图蓝图注册方式不变（``tcp_censor_bp`` 等第三方蓝图仍在 ``app.py`` 注册）
- ``app.py`` 中的 ``app``、``state`` 模块级变量保持，测试用例 ``import app as pressure_app`` 无需修改
"""

from .constants import (
    VALID_SERVER_PROTOCOLS,
    GEOIP_CACHE_FILE,
    GEOIP_LOCAL_DB_FILE,
    GEOIP_CACHE_TTL_SECONDS,
    GEOIP_BATCH_SIZE,
    ATTACK_RESOURCES_ROOT,
    SUBDIVISION_COUNTRY_CODES,
    CHINA_AREA_ALIASES,
    COUNTRY_NAME_TO_CODE,
    TestMethod,
    TestStatus,
    TestConfig,
    TestStats,
)
from .state import GlobalState

__all__ = [
    "VALID_SERVER_PROTOCOLS",
    "GEOIP_CACHE_FILE",
    "GEOIP_LOCAL_DB_FILE",
    "GEOIP_CACHE_TTL_SECONDS",
    "GEOIP_BATCH_SIZE",
    "ATTACK_RESOURCES_ROOT",
    "SUBDIVISION_COUNTRY_CODES",
    "CHINA_AREA_ALIASES",
    "COUNTRY_NAME_TO_CODE",
    "TestMethod",
    "TestStatus",
    "TestConfig",
    "TestStats",
    "GlobalState",
]
