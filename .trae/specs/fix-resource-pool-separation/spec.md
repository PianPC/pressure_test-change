# 修复资源池协议隔离与 IP 资源一致性 Spec

## Why

用户先前用 AI 修改代码时，将"资源池"（Resource Pool）页面改为所有协议共享同一个文件夹（`shared/ip_lists/`），导致切换 TCP/DNS/Memcached/NTP 协议标签时看到的资源完全相同。但用户的本意是：

1. **"攻击资源获取"面板中每个协议的"IP资源"下拉框**：应展示与"资源管理"一致的资源（共享输入 IP 候选池），用户在此选择要扫描的 IP 文件。
2. **"资源池"页面**：应按协议隔离，每个协议有独立的文件夹，因为不同协议的优质 IP 是不一样的。

目前的问题是：`list_protocol_resources(proto)` 同时扫描共享目录和协议本地 legacy 目录，且共享目录中所有资源默认标记为 `ALL_PROTOCOLS`，导致所有协议的"IP资源"下拉和"资源池"页面都展示相同的共享资源，无法体现协议间的差异。

## What Changes

### 1. 统一"IP资源"下拉框数据源 —— 仅读取共享池
- 修改每个协议的 `list_resources()` 逻辑，使其仅从 `shared/ip_lists/`（资源管理目录）读取资源，不再扫描协议本地 legacy 目录
- 确保前端各协议"IP资源"下拉框展示的内容与"资源管理"模态框完全一致
- 删除/弃用 `list_protocol_resources()` 中对 `legacy_resource_roots()` 的扫描（仅保留共享池读取）

### 2. 资源池按协议隔离 —— 每个协议独立文件夹
- 为每个协议建立独立的质量 IP 池目录：`attack_resources/{proto}/qualified_pool/`
- 扫描任务完成后，将 `qualified_ips.txt` 自动聚合到对应协议的 `qualified_pool/` 目录
- "资源池"页面切换协议标签时，展示该协议独立的质量 IP 池
- 资源池页面保留地图地理分布展示、统计信息，但数据源切换为协议独立的质量 IP 池

### 3. 明确概念边界
- **资源管理** = 共享输入 IP 候选池（爬虫获取 + 手动添加），所有协议共享
- **IP资源下拉框** = 从资源管理读取，与资源管理展示一致
- **资源池** = 按协议隔离的质量 IP 结果池（扫描输出），每个协议独立

## Impact

- **Affected code**:
  - `attack_resources/shared/ip_resource_catalog.py` — `list_protocol_resources()` 逻辑修改
  - `attack_resources/shared/attack_resource_api.py` — 各 Adapter 的 `list_resources()`、新增质量 IP 聚合接口
  - `attack_resources/tcp/code/routes.py` — TCP 扫描完成后聚合 quality IPs
  - `attack_resources/dns/code/routes.py` — DNS 扫描完成后聚合
  - `attack_resources/memcached/code/routes.py` — Memcached 扫描完成后聚合
  - `attack_resources/ntp/code/routes.py` — NTP 扫描完成后聚合
  - `app.py` — `list_server_sources()` 等资源池相关函数改为读取协议独立的质量 IP 池
  - `static/script.js` — 资源池页面数据源切换、IP资源下拉框渲染逻辑
  - `templates/index.html` — 资源池页面文案调整

## ADDED Requirements

### Requirement: 协议独立质量 IP 池
系统 SHALL 为每个协议（TCP、DNS、Memcached、NTP）维护独立的质量 IP 池目录 `attack_resources/{proto}/qualified_pool/`。

#### Scenario: 扫描完成后自动聚合
- **WHEN** 任一协议的扫描任务完成并生成了 `qualified_ips.txt`
- **THEN** 系统将该次扫描的优质 IP 追加聚合到 `attack_resources/{proto}/qualified_pool/qualified_pool.txt`
- **AND** 去重后更新该文件

#### Scenario: 资源池页面按协议展示
- **WHEN** 用户在"资源池"页面切换协议标签
- **THEN** 页面展示该协议独立质量 IP 池中的 IP 及其地理分布
- **AND** 不同协议标签展示不同的 IP 集合

### Requirement: IP资源下拉框与资源管理一致
系统 SHALL 确保每个协议的"IP资源"下拉框仅展示"资源管理"中管理的共享资源，不包含协议本地 legacy 目录的文件。

#### Scenario: 下拉框展示共享池资源
- **WHEN** 用户打开某协议的"IP资源"下拉框
- **THEN** 展示的资源列表与"资源管理"模态框中的资源列表一致
- **AND** 不包含 `attack_resources/{proto}/resources/` 下的 legacy 文件

## MODIFIED Requirements

### Requirement: 资源池数据源
**原行为**：资源池页面通过 `list_protocol_resources(proto)` 读取共享 `ip_lists/` + 协议本地 legacy 目录，所有协议展示相同的共享资源。

**修改为**：资源池页面读取 `attack_resources/{proto}/qualified_pool/` 中的协议独立质量 IP 池，每个协议展示各自的质量 IP 结果。

### Requirement: list_protocol_resources 用途收窄
**原行为**：同时扫描共享目录（按协议过滤）和协议本地 legacy 目录。

**修改为**：仅扫描共享目录 `shared/ip_lists/`，不再扫描 legacy 目录。协议本地 legacy 目录中的文件如需保留，由用户手动迁移到共享池。

## REMOVED Requirements

### Requirement: 协议本地 legacy 资源目录扫描
**Reason**: 导致"IP资源"下拉框与"资源管理"不一致，且 legacy 目录是历史遗留结构。
**Migration**: `attack_resources/{proto}/resources/ip_lists/` 和 `attack_resources/{proto}/resources/servers.txt` 中的现有文件保留在磁盘上，但不再被"IP资源"下拉框和"资源管理"展示。用户可手动将需要的文件迁移到 `shared/ip_lists/`。
