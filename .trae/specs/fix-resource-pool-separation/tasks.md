# Tasks

- [x] Task 1: 修改 `list_protocol_resources()` 仅扫描共享池
  - [x] SubTask 1.1: 在 `attack_resources/shared/ip_resource_catalog.py` 中移除 `list_protocol_resources()` 对 `legacy_resource_roots()` 的扫描调用
  - [x] SubTask 1.2: 保留仅扫描 `shared/ip_lists/` 的逻辑，并按协议字段过滤（若资源 metadata 标注了协议）
  - [x] SubTask 1.3: 验证 `legacy_resource_roots()` 函数可保留但不再被 `list_protocol_resources()` 调用（避免破坏其他潜在引用）

- [x] Task 2: 创建协议独立质量 IP 池目录与聚合工具
  - [x] SubTask 2.1: 创建四个协议的 `qualified_pool/` 目录：`attack_resources/{tcp,dns,memcached,ntp}/qualified_pool/`，每个目录添加 `.gitkeep` 占位文件
  - [x] SubTask 2.2: 新建 `attack_resources/shared/qualified_pool.py`，实现聚合工具模块，包含函数 `aggregate_quality_ips(proto, task_qualified_ips_path)`，逻辑：读取任务产物 `qualified_ips.txt` → 读取现有 `qualified_pool/qualified_pool.txt`（若存在）→ 合并去重 → 写回 `qualified_pool/qualified_pool.txt`
  - [x] SubTask 2.3: 在 `qualified_pool.py` 中增加 `list_qualified_pool_ips(proto)` 函数，返回指定协议质量 IP 池中的 IP 列表及统计信息（总数、文件大小等），供资源池页面调用

- [x] Task 3: 各协议扫描完成后调用聚合工具
  - [x] SubTask 3.1: 修改 `attack_resources/tcp/code/routes.py`，在 TCP 扫描任务完成并生成 `qualified_ips.txt` 后调用 `aggregate_quality_ips('tcp', ...)`
  - [x] SubTask 3.2: 修改 `attack_resources/dns/code/routes.py`，在 DNS 扫描任务完成后调用 `aggregate_quality_ips('dns', ...)`
  - [x] SubTask 3.3: 修改 `attack_resources/memcached/code/routes.py`，在 Memcached 扫描任务完成后调用 `aggregate_quality_ips('memcached', ...)`
  - [x] SubTask 3.4: 修改 `attack_resources/ntp/code/routes.py`，在 NTP 扫描任务完成后调用 `aggregate_quality_ips('ntp', ...)`
  - [x] SubTask 3.5: 在各协议的任务详情/日志中记录"已聚合到质量 IP 池"的提示信息

- [x] Task 4: 修改 `list_server_sources()` 读取协议独立质量 IP 池
  - [x] SubTask 4.1: 在 `app.py` 中修改 `list_server_sources(method)`，将数据源从 `list_protocol_resources(method, ATTACK_RESOURCES_ROOT)` 改为 `list_qualified_pool_ips(method)`（从 Task 2.3 导入）
  - [x] SubTask 4.2: 修改 `/api/servers/<method>` 路由的返回结构，确保包含 IP 列表、总数、地理分布统计等字段
  - [x] SubTask 4.3: 处理空质量 IP 池情况，返回友好的空状态（`ips: [], total: 0`）而非报错

- [x] Task 5: 更新前端资源池页面展示
  - [x] SubTask 5.1: 修改 `static/script.js` 中资源池页面渲染逻辑，确保切换协议标签时调用 `/api/servers/<method>` 获取该协议独立的质量 IP 列表
  - [x] SubTask 5.2: 资源池页面地理分布地图、统计卡片的数据源切换为新返回结构
  - [x] SubTask 5.3: 资源池页面在质量 IP 池为空时展示友好提示文案（如"暂无该协议的质量 IP，请先执行扫描任务"）
  - [x] SubTask 5.4: 如有必要，调整 `templates/index.html` 中资源池页面的文案说明，明确"此处展示各协议扫描产出的质量 IP"

- [x] Task 6: 验证 IP 下拉框与资源管理一致（代码审查验证）
  - [x] SubTask 6.1: 验证四个协议的"IP资源"下拉框（通过 `/api/attack-resource/{proto}/resources`）返回的内容仅来自 `shared/ip_lists/`
  - [x] SubTask 6.2: 验证下拉框内容与"资源管理"模态框（`/api/resources`）展示的资源列表完全一致
  - [x] SubTask 6.3: 验证不再展示 `attack_resources/{proto}/resources/ip_lists/` 等 legacy 目录中的文件

- [x] Task 7: 端到端验证（代码审查验证，运行时验证待用户在环境中执行）
  - [ ] SubTask 7.1: 执行一次某协议的扫描任务，验证完成后 `attack_resources/{proto}/qualified_pool/qualified_pool.txt` 被正确生成/更新
  - [ ] SubTask 7.2: 切换到"资源池"页面，验证对应协议标签展示的是该协议独立的质量 IP
  - [ ] SubTask 7.3: 切换不同协议标签，验证展示的 IP 集合不同（协议隔离生效）
  - [ ] SubTask 7.4: 在"资源管理"中手动添加/爬取新 IP 资源，验证四个协议的"IP资源"下拉框均能看到新资源

# Task Dependencies

- Task 2 必须先于 Task 3 完成（聚合工具需先存在）
- Task 2 必须先于 Task 4 完成（`list_qualified_pool_ips()` 需先实现）
- Task 3 与 Task 4 可并行进行（均依赖 Task 2，但彼此独立）
- Task 5 依赖 Task 4（前端需要后端新接口）
- Task 6 依赖 Task 1（下拉框逻辑需先修改）
- Task 7 依赖 Task 1-6 全部完成
- Task 1 与 Task 2 可并行进行（彼此独立）
