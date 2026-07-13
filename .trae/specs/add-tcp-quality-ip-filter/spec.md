# TCP 攻击资源优质 IP 筛选条件 Spec

## Why

DNS、NTP、Memcached 三个协议在扫描前均可通过"最小放大率"配置项筛选优质 IP，TCP 虽然在 `runner.py` 中已存在放大率解析逻辑，但 `ScanConfig` 缺少 `min_amplification` 字段，导致 `getattr(cfg, "min_amplification", 2.0)` 永远返回硬编码的 2.0，无法通过前端配置；同时前端表单、路由层、产物格式均未与三协议对齐，且 `success_rate` 计算存在 bug、`qualified_ips.txt` 格式不一致会污染协议级质量池。需要补齐 TCP 的优质 IP 筛选条件，使其与三协议保持一致的"最小放大率 + 最小成功率"双阈值筛选范式。

## What Changes

- 在 TCP `ScanConfig` 中新增 `min_amplification` 与 `min_success_rate` 两个配置字段，并支持从 TOML 加载
- 在 TCP 路由层 `_config_from_request` 中接收前端传入的两个筛选参数并写入 `ScanConfig`
- 在 TCP `runner.py` 中用配置字段替换硬编码的 `getattr(cfg, "min_amplification", 2.0)`，并在筛选阶段同时按放大率与成功率过滤
- 修复 `success_rate` 计算 bug（`len(ratios) / 1.0 * 100` 恒等于 100×len），改为按 `scan_count` 归一化
- 修正 `qualified_ips.txt` 输出格式，每行只写纯 IP，与 DNS/NTP/Memcached 对齐（确保 `qualified_pool.py` 聚合时不污染）
- 在 `templates/index.html` TCP 表单中新增"最小放大率"与"最小成功率"两个输入框
- 在 `static/script.js` 的 TCP `FIELD_MAP`、`readUnifiedTcpForm`、`renderTcpMeta` 中补齐两个字段的读取与回显
- 在 `attack_resources/tcp/config/scan.example.toml` 中补充两个新配置项示例

## Impact

- Affected specs: 无既有 spec 直接相关（本仓库现有 specs 均为 UI/IP 下拉相关修复）
- Affected code:
  - [config.py](file:///c:/workplace/project/mi4/pressure_test-change/attack_resources/tcp/code/tcp_censor_scan/config.py)（新增字段与 TOML 解析）
  - [runner.py](file:///c:/workplace/project/mi4/pressure_test-change/attack_resources/tcp/code/tcp_censor_scan/runner.py)（筛选逻辑、success_rate 修复、输出格式）
  - [routes.py](file:///c:/workplace/project/mi4/pressure_test-change/attack_resources/tcp/code/routes.py)（接收前端参数）
  - [scan.example.toml](file:///c:/workplace/project/mi4/pressure_test-change/attack_resources/tcp/config/scan.example.toml)（示例配置）
  - [index.html](file:///c:/workplace/project/mi4/pressure_test-change/templates/index.html)（TCP 表单输入框）
  - [script.js](file:///c:/workplace/project/mi4/pressure_test-change/static/script.js)（FIELD_MAP、表单读取、meta 回显）

## ADDED Requirements

### Requirement: TCP 优质 IP 筛选配置字段

系统 SHALL 在 TCP `ScanConfig` 中提供 `min_amplification`（默认 2.0）与 `min_success_rate`（默认 50.0）两个浮点配置字段，并支持从 TOML 配置文件加载、从前端请求覆盖。

#### Scenario: 前端传入筛选参数

- **WHEN** 前端 POST `/api/tcp-scan/start` 携带 `min_amplification=3.0` 和 `min_success_rate=70.0`
- **THEN** 路由层将两个字段写入 `ScanConfig`，扫描阶段使用这两个阈值筛选优质 IP

#### Scenario: 前端未传入筛选参数

- **WHEN** 前端请求未携带 `min_amplification` 或 `min_success_rate`
- **THEN** 路由层使用默认值 `min_amplification=2.0`、`min_success_rate=50.0`，行为与当前硬编码一致（向后兼容）

### Requirement: TCP 双阈值优质 IP 筛选

系统 SHALL 在 TCP `extract_qualified_ips` 阶段同时按最小放大率与最小成功率筛选 IP，仅保留平均放大率 ≥ `min_amplification` 且成功率 ≥ `min_success_rate` 的 IP，并按平均放大率降序排序后写入 `qualified_ips.txt`。

#### Scenario: IP 同时满足两个阈值

- **WHEN** 某 IP 在放大测试日志中平均放大率为 3.5、成功率为 80%
- **AND** 配置 `min_amplification=2.0`、`min_success_rate=50.0`
- **THEN** 该 IP 被保留并写入 `qualified_ips.txt`，每行只写纯 IP（不带 `ratio=`、`success_rate=` 后缀）

#### Scenario: IP 放大率不达标

- **WHEN** 某 IP 平均放大率为 1.5（低于 `min_amplification=2.0`）
- **THEN** 该 IP 被过滤，不写入 `qualified_ips.txt`

#### Scenario: IP 成功率不达标

- **WHEN** 某 IP 平均放大率为 5.0（满足放大率阈值），但成功率仅 30%（低于 `min_success_rate=50.0`）
- **THEN** 该 IP 被过滤，不写入 `qualified_ips.txt`

### Requirement: TCP success_rate 正确归一化

系统 SHALL 将 TCP 放大测试的 `success_rate` 按 `scan_count` 归一化计算，公式为 `success_rate = 实际响应次数 / scan_count × 100`，取值范围 0–100。

#### Scenario: 多次扫描部分响应

- **WHEN** `scan_count=10`，某 IP 在日志中产生了 7 次有效的 `amplification_ratio` 记录
- **THEN** 该 IP 的 `success_rate` 计算为 70.0

### Requirement: TCP qualified_ips.txt 纯 IP 格式

系统 SHALL 将 TCP `qualified_ips.txt` 输出为每行一个纯 IP（与 DNS/NTP/Memcached 完全一致），头部注释行以 `#` 开头说明阈值与生成时间，确保 `qualified_pool.py` 的 `_read_ip_lines` 能正确解析。

#### Scenario: 聚合到协议级质量池

- **WHEN** TCP 任务完成，`qualified_ips.txt` 包含纯 IP 列表
- **THEN** `aggregate_quality_ips("tcp", ...)` 正确读取每个 IP，`attack_resources/tcp/qualified_pool/qualified_pool.txt` 与 `attack_resources/tcp/resources/ip_lists/qualified_pool.txt` 中均为纯 IP 行

### Requirement: TCP 前端筛选条件输入框

系统 SHALL 在 `templates/index.html` 的 TCP 表单中提供"最小放大率"与"最小成功率"两个数值输入框，默认值分别为 2.0 与 50.0，并在任务详情页 meta 区域回显当前任务的阈值。

#### Scenario: 用户调整阈值

- **WHEN** 用户在 TCP 表单中将"最小放大率"改为 5.0、"最小成功率"改为 80.0 并提交
- **THEN** 任务详情页 meta 区域显示"最小放大率: 5.0"、"最小成功率: 80.0"

## MODIFIED Requirements

### Requirement: TCP ScanConfig 字段集合

TCP `ScanConfig`（frozen dataclass）在原有字段基础上增加 `min_amplification: float = 2.0` 与 `min_success_rate: float = 50.0` 两个字段；`load_config` 支持从 TOML 的 `[amplify]` 段读取 `min_amplification` 与 `min_success_rate`。

### Requirement: TCP 优质 IP 提取阶段

TCP `extract_qualified_ips` 不再使用 `getattr(cfg, "min_amplification", 2.0)` 兜底，改为直接读取 `cfg.min_amplification` 与 `cfg.min_success_rate`；`_parse_amplification_log_for_qualified` 增加最小成功率参数，返回的每条记录包含 `ip`、`ratio`、`success_rate` 三个字段；`_write_qualified_ips` 每行只写纯 IP。
