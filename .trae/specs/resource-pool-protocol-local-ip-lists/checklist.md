# Checklist

## 后端：新增协议本地文件列表与路径解析函数（ip_resource_catalog.py）

- [x] `list_protocol_local_resources(protocol, attack_resources_root)` 函数已实现，扫描 `{proto}/resources/ip_lists/` 下 `.txt` 文件
- [x] `list_protocol_local_resources()` 目录不存在时返回空列表，不抛异常
- [x] `list_protocol_local_resources()` 返回的记录 `location_label` 标注为 "{协议名} 目录"（如 "TCP 目录"）
- [x] `resolve_protocol_local_resource_path(protocol, identifier, attack_resources_root)` 函数已实现，仅在 `{proto}/resources/ip_lists/` 中解析
- [x] `resolve_protocol_local_resource_path()` 文件不存在时返回 None

## 后端：资源池文件列表数据源切换（app.py）

- [x] `_list_server_file_sources(method)` 调用 `list_protocol_local_resources()` 而非 `list_protocol_resources()`
- [x] `/api/servers/{proto}/files` 返回的文件来自 `{proto}/resources/ip_lists/`
- [x] `/api/servers/{proto}/files` 不再返回 `shared/ip_lists/` 中的文件
- [x] 返回的文件元信息结构与前端期望一致（id、name、full_path、entry_count 等）

## 后端：资源池地图数据源切换（app.py）

- [x] `list_server_sources(method)` 读取 `{proto}/resources/ip_lists/` 下所有 `.txt` 文件的 IP
- [x] IP 列表合并去重后返回
- [x] 空文件列表时返回 `{ips: [], total: 0, geo_distribution: [], ...}` 而非报错
- [x] 有 IP 时返回结构包含 ips、total、geo_distribution、located_count、unresolved_count
- [x] 不再调用 `list_qualified_pool_ips()` 读取 `qualified_pool/`

## 后端：路径解析适配（app.py）

- [x] `resolve_server_source()` 调用 `resolve_protocol_local_resource_path()` 而非 `resolve_protocol_resource_path()`
- [x] `resolve_server_sources()`、`get_effective_server_file()` 等依赖函数仍正常工作
- [x] 资源池文件编辑（GET/POST/PUT `/api/servers/{proto}/file`）操作的文件位于 `{proto}/resources/ip_lists/`

## 后端：聚合后同步到协议本地目录（qualified_pool.py）

- [x] `aggregate_quality_ips()` 在写入 `qualified_pool/qualified_pool.txt` 后，同步复制到 `{proto}/resources/ip_lists/qualified_pool.txt`
- [x] 目标目录不存在时自动创建
- [x] 返回字典包含 `synced_path` 字段
- [x] 同步失败时记录 warning 日志但不中断主流程

## 目录结构

- [x] `attack_resources/tcp/resources/ip_lists/` 已存在（含国家 txt 文件）
- [x] `attack_resources/dns/resources/ip_lists/` 目录已创建（含 .gitkeep）
- [x] `attack_resources/memcached/resources/ip_lists/` 目录已创建（含 .gitkeep）
- [x] `attack_resources/ntp/resources/ip_lists/` 目录已创建（含 .gitkeep）

## 前端验证

- [x] 资源池页面切换协议标签时，文件列表展示各自协议本地 `{proto}/resources/ip_lists/` 中的文件
- [x] 资源池地图展示该协议本地文件中的 IP 及地理分布
- [x] 不同协议标签展示不同的文件列表和 IP 集合（协议隔离生效）
- [x] 空目录协议标签展示友好空状态提示

## IP 资源下拉框不受影响

- [x] `/api/attack-resource/{proto}/resources` 仍读取 `shared/ip_lists/`
- [x] "攻击资源获取"面板的 IP 资源下拉框展示共享池资源，与"资源管理"一致
- [x] IP 资源下拉框不展示 `{proto}/resources/ip_lists/` 中的文件

## 端到端验证（运行时，待用户在环境中执行）

- [ ] 执行一次某协议扫描任务后，`{proto}/resources/ip_lists/qualified_pool.txt` 被正确同步生成
- [ ] 资源池页面对应协议标签展示同步后的质量 IP 文件
- [ ] 切换不同协议标签，展示的文件列表和 IP 集合不同
