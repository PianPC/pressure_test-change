# 资源池数据源切换为协议本地 ip_lists Spec

## Why

资源池页面的文件列表仍通过 `_list_server_file_sources()` → `list_protocol_resources()` 读取 `shared/ip_lists/`（共享输入候选池），导致所有协议标签展示相同的共享文件。但不同协议的优质 IP 不同——对 TCP 优质的 IP 对 Memcached 未必优质，资源池应按协议隔离，读取各协议本地 `attack_resources/{proto}/resources/ip_lists/` 中的文件。

前一 spec（`fix-resource-pool-separation`）仅将资源池地图显示（`list_server_sources`）切换到 `qualified_pool/`，但**未修改文件列表数据源**，导致文件列表仍展示共享文件。

## What Changes

### 1. 资源池文件列表数据源切换
- 修改 `app.py` 中 `_list_server_file_sources(method)`，不再调用 `list_protocol_resources()`（读取 `shared/ip_lists/`），改为扫描 `{proto}/resources/ip_lists/` 目录
- 在 `ip_resource_catalog.py` 中新增 `list_protocol_local_resources()` 函数，扫描协议本地 `resources/ip_lists/` 目录并返回文件元信息

### 2. 资源池地图数据源切换
- 修改 `app.py` 中 `list_server_sources(method)`，不再调用 `list_qualified_pool_ips()` 读取 `qualified_pool/`，改为读取 `{proto}/resources/ip_lists/` 下所有 `.txt` 文件的 IP 并聚合去重
- 地理分布统计基于聚合后的 IP 列表计算

### 3. 扫描输出聚合后同步到协议本地目录
- 保留 `qualified_pool.py` 中 `aggregate_quality_ips()` 现有聚合逻辑（聚合到 `{proto}/qualified_pool/qualified_pool.txt`）
- 聚合完成后新增同步步骤：将 `qualified_pool.txt` 复制到 `{proto}/resources/ip_lists/qualified_pool.txt`
- `qualified_pool/` 作为内部聚合存储保留，`resources/ip_lists/` 作为资源池展示目录

### 4. 路径解析适配
- 在 `ip_resource_catalog.py` 中新增 `resolve_protocol_local_resource_path()` 函数，仅在 `{proto}/resources/ip_lists/` 中解析文件路径
- 修改 `app.py` 中 `resolve_server_source()` 使用新函数，不再调用 `resolve_protocol_resource_path()`（该函数同时搜索 shared 目录）

### 5. IP 资源下拉框不变
- "攻击资源获取"面板的 IP 资源下拉框仍通过 `list_protocol_resources()` 读取 `shared/ip_lists/`，与本变更无关

## Impact

- **Affected specs**: `fix-resource-pool-separation`（前一 spec 的 qualified_pool 地图显示方案被修改为读取 resources/ip_lists）
- **Affected code**:
  - `attack_resources/shared/ip_resource_catalog.py` — 新增 `list_protocol_local_resources()`、`resolve_protocol_local_resource_path()`
  - `attack_resources/shared/qualified_pool.py` — `aggregate_quality_ips()` 新增同步步骤
  - `app.py` — `_list_server_file_sources()`、`list_server_sources()`、`resolve_server_source()` 数据源切换
  - `attack_resources/{dns,memcached,ntp}/resources/ip_lists/.gitkeep` — 新建目录占位
  - `static/script.js` — 空状态提示文案微调（如需要）

## ADDED Requirements

### Requirement: 协议本地 IP 文件列表函数
系统 SHALL 提供 `list_protocol_local_resources(protocol, attack_resources_root)` 函数，扫描 `attack_resources/{proto}/resources/ip_lists/` 目录下所有 `.txt` 文件并返回文件元信息列表。

#### Scenario: 目录存在且有文件
- **WHEN** 调用 `list_protocol_local_resources("tcp", root)` 且 `tcp/resources/ip_lists/` 含 `.txt` 文件
- **THEN** 返回每个文件的元信息（id、name、full_path、entry_count 等）
- **AND** `location_label` 标注为 "TCP 目录"

#### Scenario: 目录不存在
- **WHEN** 调用 `list_protocol_local_resources("dns", root)` 且 `dns/resources/ip_lists/` 不存在
- **THEN** 返回空列表，不报错

### Requirement: 聚合后同步到协议本地展示目录
系统 SHALL 在 `aggregate_quality_ips()` 完成向 `qualified_pool/qualified_pool.txt` 聚合后，将该文件同步复制到 `{proto}/resources/ip_lists/qualified_pool.txt`。

#### Scenario: 聚合后同步成功
- **WHEN** 某协议扫描完成，`aggregate_quality_ips()` 成功写入 `qualified_pool/qualified_pool.txt`
- **THEN** 系统将 `qualified_pool.txt` 复制到 `{proto}/resources/ip_lists/qualified_pool.txt`
- **AND** 若目标目录不存在则自动创建

### Requirement: 协议本地路径解析函数
系统 SHALL 提供 `resolve_protocol_local_resource_path(protocol, identifier, attack_resources_root)` 函数，仅在 `{proto}/resources/ip_lists/` 目录中解析文件标识符为路径。

#### Scenario: 解析文件名
- **WHEN** 调用 `resolve_protocol_local_resource_path("tcp", "qualified_pool.txt", root)`
- **THEN** 返回 `tcp/resources/ip_lists/qualified_pool.txt` 的完整路径（若存在）

#### Scenario: 文件不存在
- **WHEN** 调用 `resolve_protocol_local_resource_path("dns", "nonexistent.txt", root)` 且文件不存在
- **THEN** 返回 `None`

## MODIFIED Requirements

### Requirement: 资源池文件列表数据源
**原行为**：`_list_server_file_sources(method)` 调用 `list_protocol_resources(method, root)`，扫描 `shared/ip_lists/`，所有协议展示相同的共享文件。

**修改为**：`_list_server_file_sources(method)` 调用 `list_protocol_local_resources(method, root)`，扫描 `{proto}/resources/ip_lists/`，每个协议展示各自本地目录中的文件。

### Requirement: 资源池地图 IP 数据源
**原行为**：`list_server_sources(method)` 调用 `list_qualified_pool_ips(method)`，读取 `{proto}/qualified_pool/qualified_pool.txt` 中的 IP。

**修改为**：`list_server_sources(method)` 读取 `{proto}/resources/ip_lists/` 下所有 `.txt` 文件中的 IP，合并去重后返回 IP 列表与地理分布统计。

### Requirement: 资源池文件路径解析
**原行为**：`resolve_server_source(method, source)` 调用 `resolve_protocol_resource_path(method, source, root)`，同时搜索 `shared/ip_lists/` 和协议本地目录。

**修改为**：`resolve_server_source(method, source)` 调用 `resolve_protocol_local_resource_path(method, source, root)`，仅在 `{proto}/resources/ip_lists/` 中解析。

## REMOVED Requirements

### Requirement: 资源池文件列表读取共享池
**Reason**: 资源池应展示协议本地质量 IP 文件，而非共享输入候选池。
**Migration**: `shared/ip_lists/` 中的文件仍由"资源管理"和"IP资源下拉框"使用，不受影响。
