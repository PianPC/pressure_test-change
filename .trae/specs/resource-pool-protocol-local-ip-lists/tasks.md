# Tasks

- [x] Task 1: 在 `ip_resource_catalog.py` 新增协议本地文件列表与路径解析函数
  - [x] SubTask 1.1: 新增 `list_protocol_local_resources(protocol, attack_resources_root)` 函数，扫描 `{proto}/resources/ip_lists/` 下所有 `.txt` 文件，使用 `build_resource_record()` 构建元信息，`owning_protocol` 设为传入协议，`root_base` 设为本地 ip_lists 目录
  - [x] SubTask 1.2: 新增 `resolve_protocol_local_resource_path(protocol, identifier, attack_resources_root)` 函数，调用内部 `_resolve_resource_path()`，`search_roots` 仅包含 `{proto}/resources/ip_lists/` 目录
  - [x] SubTask 1.3: 验证目录不存在时返回空列表 / None，不抛异常

- [x] Task 2: 修改 `app.py` 中 `_list_server_file_sources()` 数据源
  - [x] SubTask 2.1: 将 `_list_server_file_sources(method)` 中的 `list_protocol_resources(method, ATTACK_RESOURCES_ROOT)` 替换为 `list_protocol_local_resources(method, ATTACK_RESOURCES_ROOT)`
  - [x] SubTask 2.2: 导入 `list_protocol_local_resources`（更新 `app.py` 顶部 import 语句）
  - [x] SubTask 2.3: 验证返回的文件元信息结构与前端期望一致（id、name、display_name、path、full_path、entry_count、editable、location_label 等）

- [x] Task 3: 修改 `app.py` 中 `list_server_sources()` 地图数据源
  - [x] SubTask 3.1: 移除对 `list_qualified_pool_ips(method)` 的调用，改为通过 `_list_server_file_sources(method)` 获取文件列表，再逐文件读取 IP（复用 `read_server_entries_from_file()`），合并去重
  - [x] SubTask 3.2: 空文件列表时返回 `{ips: [], total: 0, geo_distribution: [], ...}` 友好空状态
  - [x] SubTask 3.3: 有 IP 时调用 `build_geo_points(method, entries=ips)` 计算地理分布，返回结构与原有一致（ips、total、geo_distribution、located_count、unresolved_count）
  - [x] SubTask 3.4: 清理不再使用的 `list_qualified_pool_ips` 导入（若 `app.py` 中无其他引用）

- [x] Task 4: 修改 `app.py` 中 `resolve_server_source()` 路径解析
  - [x] SubTask 4.1: 将 `resolve_server_source()` 中的 `resolve_protocol_resource_path(method, source, ATTACK_RESOURCES_ROOT)` 替换为 `resolve_protocol_local_resource_path(method, source, ATTACK_RESOURCES_ROOT)`
  - [x] SubTask 4.2: 导入 `resolve_protocol_local_resource_path`（更新 import 语句）
  - [x] SubTask 4.3: 验证 `resolve_server_sources()`、`get_effective_server_file()` 等依赖函数仍正常工作（它们调用 `resolve_server_source()`）

- [x] Task 5: 修改 `qualified_pool.py` 中 `aggregate_quality_ips()` 新增同步步骤
  - [x] SubTask 5.1: 在 `aggregate_quality_ips()` 写入 `qualified_pool/qualified_pool.txt` 后，新增同步逻辑：将 `qualified_pool.txt` 复制到 `{proto}/resources/ip_lists/qualified_pool.txt`
  - [x] SubTask 5.2: 目标目录不存在时 `os.makedirs(..., exist_ok=True)` 自动创建
  - [x] SubTask 5.3: 在返回字典中增加 `synced_path` 字段记录同步目标路径
  - [x] SubTask 5.4: 同步失败时记录 warning 日志但不中断主流程（聚合已成功）

- [x] Task 6: 创建 dns/memcached/ntp 的 `resources/ip_lists/` 目录
  - [x] SubTask 6.1: 创建 `attack_resources/dns/resources/ip_lists/.gitkeep`
  - [x] SubTask 6.2: 创建 `attack_resources/memcached/resources/ip_lists/.gitkeep`
  - [x] SubTask 6.3: 创建 `attack_resources/ntp/resources/ip_lists/.gitkeep`
  - [x] SubTask 6.4: 确认 `attack_resources/tcp/resources/ip_lists/` 已存在（含 7 个国家 txt 文件）

- [x] Task 7: 前端空状态文案适配（代码审查验证）
  - [x] SubTask 7.1: 检查 `static/script.js` 中 `loadServerGeoMap()` 的空状态提示文案，确保对"暂无该协议的质量 IP"类提示仍适用（资源池读取协议本地文件，空时提示合理）
  - [x] SubTask 7.2: 检查 `templates/index.html` 中资源池页面文案，确认"按协议隔离的质量 IP 结果池"描述仍准确

- [x] Task 8: 代码审查验证（确保 IP 资源下拉框不受影响）
  - [x] SubTask 8.1: 验证 `/api/attack-resource/{proto}/resources` 仍通过 `list_protocol_resources()` 读取 `shared/ip_lists/`，未受本变更影响
  - [x] SubTask 8.2: 验证 `/api/servers/{proto}/files` 返回的文件来自 `{proto}/resources/ip_lists/`，不再来自 `shared/ip_lists/`
  - [x] SubTask 8.3: 验证 `/api/servers/{proto}` 返回的 IP 来自 `{proto}/resources/ip_lists/` 文件，不再来自 `qualified_pool/`
  - [x] SubTask 8.4: 验证四个协议切换标签时，文件列表和地图展示各自协议本地的数据（协议隔离生效）

# Task Dependencies

- Task 1 必须先于 Task 2、Task 4 完成（新函数需先存在）
- Task 2 与 Task 3 可并行（均修改 app.py 不同函数，但依赖 Task 1）
- Task 4 依赖 Task 1（需要 `resolve_protocol_local_resource_path`）
- Task 5 独立于 Task 1-4（仅修改 qualified_pool.py）
- Task 6 独立于 Task 1-5（仅创建目录）
- Task 7 依赖 Task 2、Task 3（前端文案验证需后端就绪）
- Task 8 依赖 Task 1-6 全部完成
