# Shodan/FOFA API 密钥配置与新用户引导 Spec

## Why

Shodan 与 FOFA 是当前 IP 资源自动获取的关键数据源，但 API 密钥当前硬编码在 `attack_resources/shared/config.py` 中（默认空字符串），用户无法通过 UI 配置。新用户在新设备上首次使用时，选择 Shodan/FOFA 后只能看到 `获取失败: Shodan API key not configured` 红字提示，没有任何引导说明密钥从何处获取、如何填写，导致新用户流程中断。需要：
1. 提供一个不依赖源码、可在运行时配置和持久化的 API 密钥存储方式；
2. 在 UI 中提供完整的密钥配置面板与新用户分步引导（注册账号 → 找到密钥页 → 复制 → 填写 → 测试 → 保存）；
3. 在密钥未配置时，禁止盲调用并直接引导用户进入配置流程。

## What Changes

### 1. 凭据持久化存储（与源码解耦）
- 新增 `attack_resources/shared/api_credentials.json`（默认不存在；在 `.gitignore` 中加入忽略规则）作为本地凭据持久化文件
- 新增 `attack_resources/shared/credential_store.py`，提供 `load_credentials()` / `save_credentials(source, data)` / `clear_credentials(source)` / `get_credentials(source)` 函数
- 凭据文件格式：
  ```json
  {
    "shodan": {"api_key": "...", "updated_at": "ISO8601"},
    "fofa":   {"email": "...", "key": "...", "updated_at": "ISO8601"}
  }
  ```

### 2. Spider 凭据热加载
- 修改 `ShodanSpider.__init__` / `FOFASpider.__init__`，使其不再仅从 `SPIDER_CONFIG` 读取 `api_key`/`email`/`key`，而是先读 `credential_store.get_credentials()` 中的值，`SPIDER_CONFIG` 作为 base_url、queries、limit 等非凭据配置来源
- 在 `ShodanSpider.fetch()` / `FOFASpider.fetch()` 入口处重新读取凭据（避免 Spider 单例缓存旧值）
- 保留 `check_api_key()` / `check_credentials()` 方法用于"测试连接"

### 3. 后端凭据 API
新增以下路由（在 `attack_resource_api.py` 中）：
- `GET /api/attack-resource/credentials` — 返回各 source 的配置状态（不返回明文凭据），例如：
  ```json
  {"success": true, "credentials": {
    "shodan": {"configured": false, "updated_at": null},
    "fofa":   {"configured": false, "updated_at": null}
  }}
  ```
- `POST /api/attack-resource/credentials/<source>` — 保存凭据（请求体：shodan `{api_key}`，fofa `{email, key}`），保存后立即调用对应 `check_*` 方法返回 `valid`/`error`
- `DELETE /api/attack-resource/credentials/<source>` — 清除该 source 的凭据
- `POST /api/attack-resource/credentials/<source>/test` — 仅测试现有凭据（不保存），返回 `{valid, error}`

### 4. UI 凭据状态展示
- 修改 `templates/index.html` 的 `#ipResourceFetchModal` 中 `#ipResourceFetchSource` 选项，在 Shodan/FOFA 选项文本旁动态展示配置状态徽标（"未配置"/"已配置"），徽标由 `static/script.js` 在打开 modal 和保存凭据后刷新
- 当用户切换到 Shodan/FOFA 且该 source 未配置时：
  - 在 `#ipResourceFetchParams` 区域顶部显示红色告警条："该数据源需要 API 密钥，当前未配置。点击「立即配置」开始引导。"
  - 告警条内含「立即配置」按钮，点击打开 `#apiCredentialModal`
  - 同时禁用「开始获取」按钮（`disabled` + 视觉置灰），仅在该 source 已配置时恢复可点

### 5. API 凭据配置 Modal + 新用户引导
- 新增 `#apiCredentialModal`（结构与 `#ipResourceFetchModal` 一致），包含：
  - source 选择器（Shodan / FOFA 切换）
  - **新用户分步引导面板**（始终可见，编号步骤）：
    - **Shodan 步骤**：
      1. 注册账号：访问 [https://account.shodan.io/register](https://account.shodan.io/register)（外链按钮），完成注册
      2. 登录后访问 [https://account.shodan.io](https://account.shodan.io) 页面
      3. 在「API Key」区域复制您的 API Key
      4. 粘贴到下方「API Key」输入框
      5. 点击「测试连接」验证密钥可用
      6. 点击「保存」完成配置
    - **FOFA 步骤**：
      1. 注册账号：访问 [https://fofa.info/](https://fofa.info/)（外链按钮），完成注册并登录
      2. 访问 [https://fofa.info/userInfo](https://fofa.info/userInfo) 个人中心
      3. 在「个人资料」中找到「Email」和「API Key」
      4. 分别填入下方对应输入框
      5. 点击「测试连接」
      6. 点击「保存」
  - 凭据输入表单（Shodan: 1 个 input；FOFA: 2 个 input），输入框默认 `type="password"` + 显示眼睛图标切换明文
  - 操作按钮：「测试连接」（不保存，调用 `/test`）、「保存」（调用 POST `/credentials/<source>`，后端会再次测试）、「清除」（调用 DELETE，仅凭据已配置时显示）
  - 状态文本区 `#apiCredentialStatus`：显示测试结果、保存成功/失败、清除结果
  - 关闭 modal 时若凭据刚刚保存成功，则刷新 `#ipResourceFetchModal` 的状态徽标和「开始获取」按钮可用性

### 6. 首次启动检测
- 在 `templates/index.html` 页面加载或用户首次打开 `#ipResourceFetchModal` 时，调用 `GET /credentials` 获取凭据状态并缓存到 `IPResourceUi`
- 若 Shodan 与 FOFA 均未配置且用户从未见过引导，可在 `#ipResourceFetchModal` 顶部展示一次性提示条："首次使用 Shodan/FOFA？请先配置 API 密钥。"（提示条关闭后本次会话不再显示）

## Impact

- **Affected specs**：无直接影响（其他 spec 涉及资源池文件路径与协议本地 ip_lists，与本变更正交）
- **Affected code**：
  - 新增 `attack_resources/shared/api_credentials.json`（运行时生成，gitignored）
  - 新增 `attack_resources/shared/credential_store.py`
  - 修改 `attack_resources/shared/spiders/shodan_spider.py` — 凭据热加载
  - 修改 `attack_resources/shared/spiders/fofa_spider.py` — 凭据热加载
  - 修改 `attack_resources/shared/attack_resource_api.py` — 新增 4 个凭据路由
  - 修改 `templates/index.html` — 新增 `#apiCredentialModal`、修改 `#ipResourceFetchModal` 选项与告警条
  - 修改 `static/script.js` — 新增 `ApiCredentialManager` 模块、`IPResourceUi` 状态徽标/禁用逻辑、引导按钮事件
  - 修改 `.gitignore` — 忽略 `attack_resources/shared/api_credentials.json`

## ADDED Requirements

### Requirement: 凭据持久化存储
系统 SHALL 在 `attack_resources/shared/api_credentials.json` 文件中持久化 Shodan 与 FOFA 的 API 凭据，该文件不纳入版本控制。

#### Scenario: 文件不存在时读取
- **WHEN** 调用 `load_credentials()` 且 `api_credentials.json` 不存在
- **THEN** 返回 `{"shodan": None, "fofa": None}`，不抛出异常

#### Scenario: 保存 Shodan 凭据
- **WHEN** 调用 `save_credentials("shodan", {"api_key": "ABC123"})`
- **THEN** 文件被创建或更新，`shodan` 字段包含 `{"api_key": "ABC123", "updated_at": "<当前ISO时间>"}`
- **AND** `fofa` 字段（若已存在）保持不变

#### Scenario: 清除 FOFA 凭据
- **WHEN** 调用 `clear_credentials("fofa")`
- **THEN** 文件中 `fofa` 字段被移除（或置为 `null`）
- **AND** `shodan` 字段保持不变

#### Scenario: 文件被意外删除
- **WHEN** `api_credentials.json` 在运行期间被外部删除
- **THEN** 后续 `get_credentials(source)` 返回 `None`，Spider 调用 `fetch()` 时返回 `{"success": False, "error": "...not configured"}`

### Requirement: Spider 凭据热加载
ShodanSpider 与 FOFASpider SHALL 在每次 `fetch()` 调用时从 `credential_store` 重新读取凭据，而非仅依赖构造时缓存的值。

#### Scenario: 保存新凭据后立即生效
- **WHEN** 用户通过 API 保存了新的 Shodan API Key
- **AND** 立即调用 `IPResourceManager.fetch_auto_resources("shodan", params)`
- **THEN** Spider 使用新保存的 API Key 发起请求，不需要重启服务

#### Scenario: 凭据被清除后调用
- **WHEN** 用户清除 FOFA 凭据后调用 `fetch_auto_resources("fofa", params)`
- **THEN** 返回 `{"success": False, "error": "FOFA email or key not configured"}`

### Requirement: 凭据查询 API
系统 SHALL 提供 `GET /api/attack-resource/credentials` 端点，返回每个 source 的配置状态，且不暴露明文凭据。

#### Scenario: 查询未配置状态
- **WHEN** 调用 `GET /credentials` 且两个 source 均未配置
- **THEN** 返回 `{"success": true, "credentials": {"shodan": {"configured": false, "updated_at": null}, "fofa": {"configured": false, "updated_at": null}}}`

#### Scenario: 查询已配置状态
- **WHEN** Shodan 已配置，FOFA 未配置
- **THEN** 返回 `shodan.configured = true`、`shodan.updated_at` 为 ISO 时间字符串
- **AND** 返回 `fofa.configured = false`
- **AND** 响应体中**不**包含任何 `api_key` / `email` / `key` 明文字段

### Requirement: 凭据保存 API
系统 SHALL 提供 `POST /api/attack-resource/credentials/<source>` 端点，保存指定 source 的凭据并立即返回测试结果。

#### Scenario: 保存有效的 Shodan API Key
- **WHEN** POST `/credentials/shodan` 请求体为 `{"api_key": "<有效key>"}`
- **THEN** 凭据写入 `api_credentials.json`
- **AND** 后端调用 `ShodanSpider.check_api_key()` 验证
- **AND** 返回 `{"success": true, "valid": true, "user": "<email>"}`
- **AND** `updated_at` 字段被记录

#### Scenario: 保存无效的 FOFA 凭据
- **WHEN** POST `/credentials/fofa` 请求体为 `{"email": "x@y.com", "key": "wrong"}`
- **THEN** 凭据仍被写入文件（允许保存无效凭据以便用户后续修改）
- **AND** 返回 `{"success": true, "valid": false, "error": "<FOFA错误信息>"}`

#### Scenario: 缺少必填字段
- **WHEN** POST `/credentials/fofa` 请求体为 `{"email": "x@y.com"}`（缺少 `key`）
- **THEN** 返回 HTTP 400，`{"success": false, "message": "缺少必填字段: key"}`
- **AND** 凭据不被写入

#### Scenario: 未知 source
- **WHEN** POST `/credentials/unknown`
- **THEN** 返回 HTTP 400，`{"success": false, "message": "未知的数据源: unknown"}`

### Requirement: 凭据测试 API
系统 SHALL 提供 `POST /api/attack-resource/credentials/<source>/test` 端点，仅测试请求体中的凭据而不持久化。

#### Scenario: 测试不保存
- **WHEN** POST `/credentials/shodan/test` 请求体为 `{"api_key": "<有效key>"}`
- **THEN** 后端构造临时 Spider 实例（或临时设置 key）调用 `check_api_key()`
- **AND** 返回 `{"success": true, "valid": true, "user": "<email>"}`
- **AND** `api_credentials.json` **不**被修改

### Requirement: 凭据清除 API
系统 SHALL 提供 `DELETE /api/attack-resource/credentials/<source>` 端点清除指定 source 的凭据。

#### Scenario: 清除已存在的凭据
- **WHEN** DELETE `/credentials/shodan` 且 Shodan 凭据已存在
- **THEN** 凭据从文件中移除
- **AND** 返回 `{"success": true, "message": "Shodan 凭据已清除"}`

#### Scenario: 清除不存在的凭据
- **WHEN** DELETE `/credentials/fofa` 且 FOFA 凭据不存在
- **THEN** 返回 `{"success": true, "message": "FOFA 凭据已清除"}`（幂等）
- **AND** 文件不被破坏

### Requirement: Fetch Modal 凭据状态展示
Fetch Modal SHALL 在 Shodan/FOFA 选项旁显示当前配置状态徽标，并在未配置时禁用「开始获取」按钮。

#### Scenario: Shodan 未配置
- **WHEN** 用户打开 Fetch Modal 且 Shodan 凭据未配置
- **THEN** `#ipResourceFetchSource` 的 Shodan 选项文本显示为 "Shodan (未配置)"
- **WHEN** 用户选中 Shodan
- **THEN** `#ipResourceFetchParams` 顶部显示红色告警条 "该数据源需要 API 密钥，当前未配置。" 含「立即配置」按钮
- **AND** `#ipResourceFetchStart` 按钮 `disabled` 并视觉置灰

#### Scenario: FOFA 已配置
- **WHEN** FOFA 凭据已配置
- **THEN** FOFA 选项文本显示为 "FOFA (已配置)"
- **AND** 选中 FOFA 时不显示告警条，「开始获取」按钮可点

#### Scenario: 点击立即配置
- **WHEN** 用户点击告警条中「立即配置」按钮
- **THEN** `#apiCredentialModal` 打开，且 source 选择器预选当前 source（Shodan 或 FOFA）

### Requirement: API 凭据配置 Modal 与新用户引导
系统 SHALL 提供一个 API 凭据配置 Modal，包含分步引导面板和输入表单。

#### Scenario: 打开 Shodan 引导
- **WHEN** 用户在 `#apiCredentialModal` 中选择 Shodan
- **THEN** 显示 Shodan 分步引导（6 步，含外链 https://account.shodan.io/register）
- **AND** 显示单个 "API Key" 输入框（`type="password"` + 显示/隐藏切换）
- **AND** 显示「测试连接」「保存」「清除」按钮（「清除」仅在已配置时显示）

#### Scenario: 测试连接成功
- **WHEN** 用户填入 API Key 并点击「测试连接」
- **THEN** 前端 POST `/credentials/shodan/test`，请求体 `{api_key}`
- **AND** 在 `#apiCredentialStatus` 显示绿色 "连接成功，账号: <email>"
- **AND** 凭据文件**不**被修改

#### Scenario: 保存成功并刷新
- **WHEN** 用户点击「保存」且后端返回 `valid: true`
- **THEN** `#apiCredentialStatus` 显示绿色 "Shodan 凭据已保存"
- **AND** 前端刷新 Fetch Modal 的状态徽标
- **AND** 若 Fetch Modal 当前选中 Shodan，则隐藏告警条并恢复「开始获取」按钮

#### Scenario: 保存失败提示
- **WHEN** 后端返回 `valid: false`
- **THEN** `#apiCredentialStatus` 显示橙色 "凭据已保存，但测试失败: <error>。可稍后重试或修改。"
- **AND** 凭据状态徽标更新为「已配置」（即使测试失败，凭据已写入）

#### Scenario: FOFA 双字段引导
- **WHEN** 用户在 `#apiCredentialModal` 中选择 FOFA
- **THEN** 显示 FOFA 分步引导（含 https://fofa.info/userInfo 外链）
- **AND** 显示 "Email" 和 "API Key" 两个输入框

### Requirement: 首次启动提示
当用户首次打开 Fetch Modal 且 Shodan 与 FOFA 均未配置时，SHALL 在 Modal 顶部展示一次性引导提示条。

#### Scenario: 首次打开且均未配置
- **WHEN** 用户首次打开 Fetch Modal 且两个 source 均未配置
- **THEN** Modal 顶部显示提示条 "首次使用 Shodan/FOFA？请先配置 API 密钥。" 含「去配置」按钮
- **AND** 用户关闭提示条后本次会话不再显示

#### Scenario: 任一 source 已配置
- **WHEN** 任一 source 已配置
- **THEN** 不显示首次提示条

## MODIFIED Requirements

### Requirement: Shodan/FOFA 凭据来源
**原行为**：`ShodanSpider.__init__` 从 `SPIDER_CONFIG["shodan"]["api_key"]` 读取凭据，构造后不再更新；用户必须编辑 `config.py` 才能配置。

**修改为**：`ShodanSpider.__init__` 仍从 `SPIDER_CONFIG` 读取非凭据配置（base_url、queries、limit_per_query、request_timeout），但凭据从 `credential_store.get_credentials("shodan")` 读取；`fetch()` 入口处重新调用 `get_credentials` 以支持热加载。FOFA 同理。

### Requirement: Fetch Modal 数据源选项展示
**原行为**：`#ipResourceFetchSource` 选项静态文本为 `<option value="shodan">Shodan (需要API密钥)</option>`。

**修改为**：选项文本由 JS 动态生成，根据凭据状态显示 "Shodan (未配置)" 或 "Shodan (已配置)"；FOFA 同理。

## REMOVED Requirements

### Requirement: 凭据硬编码于源码
**Reason**：将凭据写入 `config.py` 不安全（易被提交到 git）、不可热更新、无法在 UI 配置。
**Migration**：`SPIDER_CONFIG` 中的 `api_key` / `email` / `key` 字段保留为空字符串作为兼容默认值，但实际运行时优先从 `api_credentials.json` 读取；现有部署若已手工编辑 `config.py`，可手动迁移到 `api_credentials.json`（无自动迁移，因 `config.py` 中的值通常是空）。
