#!/usr/bin/env python3
"""多协议联合压力测试系统的 Flask 启动入口。

在 refactor/codebase 阶段 2 后，此文件变为极薄入口：

* 所有常量、GEOIP 工具、全局状态、服务器文件管理、路由注册、启动辅助
  均已拆分到 :mod:`pressure` 子包。
* 为了保持与 ``tests/`` 中 ``import app as pressure_app``、
  以及 ``pressure_app.app.test_client()`` 写法的兼容性，
  模块级仍暴露 ``app`` 与 ``state`` 两个单例。
* 所有对外路由路径、请求/响应格式保持不变。

为了让 ``mock.patch.object(app_module, "ATTACK_RESOURCES_ROOT")``
这类历史测试代码继续生效，本模块的 ``__class__`` 被替换为一个自定义
ModuleType，每当对以下“可 mock 状态”赋值时，会把值同步回
``pressure.constants``（因为 servers/geoip_utils/bootstrap/routes
内部实际使用的是 pressure.constants 里的运行时属性）：

  - ATTACK_RESOURCES_ROOT
  - GEOIP_CACHE_FILE
  - GEOIP_LOCAL_DB_FILE
  - GEOIP_CACHE_TTL_SECONDS
  - GEOIP_BATCH_SIZE
  - VALID_SERVER_PROTOCOLS
  - SUBDIVISION_COUNTRY_CODES
  - CHINA_AREA_ALIASES
  - COUNTRY_NAME_TO_CODE

此外，``load_geoip_cache``/``save_geoip_cache``/``query_geoip_local_batch``/
``query_geoip_batch`` 等函数名在 ``app`` 命名空间里 mock 时，
路由 ``pressure.routes`` 里通过 ``from pressure.geoip_utils import X``
直接绑定的名字无法感知，所以在路由 helper 里统一改成
``from . import geoip_utils as _geo``，运行时再访问属性。
"""

import sys
import types

from pressure import constants as _pressure_constants
from pressure.bootstrap import (
    check_root_privileges,
    create_app,
    create_default_server_files,
    create_required_directories,
    migrate_server_files,
    print_banner,
    print_help,
    run_development_server,
    run_startup_routines,
    setup_logging,
)
from pressure.constants import (
    ATTACK_RESOURCES_ROOT,
    CHINA_AREA_ALIASES,
    COUNTRY_NAME_TO_CODE,
    GEOIP_BATCH_SIZE,
    GEOIP_CACHE_FILE,
    GEOIP_CACHE_TTL_SECONDS,
    GEOIP_LOCAL_DB_FILE,
    SUBDIVISION_COUNTRY_CODES,
    TestConfig,
    TestMethod,
    TestStats,
    TestStatus,
    VALID_SERVER_PROTOCOLS,
)
from pressure.geoip_utils import (
    build_geo_areas,
    build_geo_points,
    is_geo_cache_complete,
    load_geoip_cache,
    normalize_geo_record,
    query_geoip_batch,
    query_geoip_local_batch,
    resolve_public_ip,
    save_geoip_cache,
)
from pressure.servers import (
    count_server_entries_in_file,
    get_default_server_file_content,
    get_effective_server_file,
    get_server_file,
    is_valid_server_method,
    list_server_source_paths,
    list_server_sources,
    read_server_entries,
    read_server_entries_from_file,
    resolve_server_source,
    resolve_server_sources,
)
from pressure.state import GlobalState

# 这些“状态型”名字一旦在本模块被替换（例如 unittest.mock.patch.object），
# 需要同步写回 pressure.constants，使拆分出去的子模块也能看到新值。
_SYNCED_TO_CONSTANTS = frozenset(
    {
        "ATTACK_RESOURCES_ROOT",
        "GEOIP_CACHE_FILE",
        "GEOIP_LOCAL_DB_FILE",
        "GEOIP_CACHE_TTL_SECONDS",
        "GEOIP_BATCH_SIZE",
        "VALID_SERVER_PROTOCOLS",
        "SUBDIVISION_COUNTRY_CODES",
        "CHINA_AREA_ALIASES",
        "COUNTRY_NAME_TO_CODE",
    }
)

# 这些函数在 app 命名空间被替换时，需要同步覆盖 pressure.geoip_utils /
# pressure.servers 里“同名属性”访问点，以保证 mock 生效。
_GEOIP_FUNCS = frozenset(
    {
        "load_geoip_cache",
        "save_geoip_cache",
        "query_geoip_local_batch",
        "query_geoip_batch",
    }
)


class _SyncedAppModule(types.ModuleType):
    """让 ``mock.patch.object(app_module, name)`` 同步覆盖拆分子模块中的值。"""

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name in _SYNCED_TO_CONSTANTS:
            setattr(_pressure_constants, name, value)
        if name in _GEOIP_FUNCS:
            import pressure.geoip_utils as _gutils

            setattr(_gutils, name, value)


# 必须在赋值 app/state 前替换，以免被 GC 或 ModuleSpec 引用的对象不一致
sys.modules[__name__].__class__ = _SyncedAppModule

# Flask 应用与全局运行期状态 —— 保持模块级单例以便测试 import。
app, state = create_app()


__all__ = [
    # Flask
    "app",
    "state",
    # 常量
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
    # GEOIP utils (保持兼容性重新导出)
    "load_geoip_cache",
    "save_geoip_cache",
    "resolve_public_ip",
    "normalize_geo_record",
    "is_geo_cache_complete",
    "query_geoip_local_batch",
    "query_geoip_batch",
    "build_geo_areas",
    "build_geo_points",
    # Servers helpers
    "is_valid_server_method",
    "get_server_file",
    "get_default_server_file_content",
    "list_server_sources",
    "list_server_source_paths",
    "count_server_entries_in_file",
    "resolve_server_source",
    "resolve_server_sources",
    "get_effective_server_file",
    "read_server_entries_from_file",
    "read_server_entries",
    # Bootstrap
    "check_root_privileges",
    "migrate_server_files",
    "create_required_directories",
    "create_default_server_files",
    "setup_logging",
    "print_banner",
    "print_help",
    "run_startup_routines",
    "run_development_server",
    "create_app",
]


if __name__ == "__main__":
    run_startup_routines()
    run_development_server(app)
