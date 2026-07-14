# Spider 凭据与资源获取失败问题修复 Spec

## Why
用户在实测中报告了 5 个叠加问题，导致 Shodan/FOFA/Sonar 三种数据源均无法获取资源：
1. 自动获取 cookie 失败，错误信息为 `No module named 'browser_cookie3'`（虽然 `requirements.txt` 已声明依赖，但用户环境未安装）
2. 手动配置 cookie 失败 —— 用户只提供了 `polito` 字段（广告/偏好 cookie），缺少 Shodan 真正的登录态字段 `shodan_session`
3. **重新配置入口缺失** —— 配置成功后，IP 资源获取面板不再显示"立即配置"按钮，用户找不到更换/重新配置 cookie 的入口
4. Shodan API 配置成功后仍然获取不到资源 —— `check_api_key` 只调用 `/account/profile`（不消耗 query credits），但免费账号 `query_credits=0`，无法执行搜索 API
5. Sonar 免费方式失败 —— Rapid7 OpenData 商业化 gating 后错误信息不够明确

这些问题叠加后，用户完全无法获取资源，且无法理解失败原因，需要系统性修复。

## What Changes

### 后端
- **`browser_cookie3` 模块缺失友好提示**：在 `auto_extract_cookies_route` 中区分 `ModuleNotFoundError` 与其他异常，未安装时返回明确安装指令（`pip install browser_cookie3==0.16.2`），不再让用户看一长串 traceback
- **手动 cookie 关键字段校验**：在 `save_cookies_route` 中对 Shodan 检查是否包含 `shodan_session`，对 FOFA 检查是否包含 `FOFA_TOKEN`；缺失时仍允许保存，但返回 warning 字段提示用户
- **Shodan API 测试返回 credits 信息**：`ShodanSpider.check_api_key` 调用 `/account/profile` 时读取 `query_credits`、`scan_credits`、`plan` 字段；`test_credentials_route` 和 `save_credentials_route` 透传这些字段；当 `query_credits <= 0` 时返回 `warning` 提示"API 有效但无搜索额度，需付费 plan"
- **Shodan API 搜索错误信息增强**：`_fetch_via_api` 捕获 HTTP 错误响应体（Shodan 返回 JSON 错误），提取 `error` 字段，明确告知"query credits exhausted"等具体原因
- **Sonar 错误信息明确化**：`SonarSpider.fetch` 区分"商业化 gating"（响应体是 HTML 登录页）与"未找到数据集"，gating 时明确告知"Rapid7 OpenData 已商业化，公开下载受限，请使用其他数据源"

### 前端
- **常驻"重新配置凭据"入口**：在 IP 资源获取面板的"已配置"分支下，也显示"重新配置凭据"按钮（次要按钮样式），点击后调用 `ApiCredentialUi.open(source)`；保持"未配置"分支下的"立即配置"按钮不变
- **API 测试结果展示 credits/plan**：`ApiCredentialUi.testConnection` 接收后端返回的 `query_credits`/`scan_credits`/`plan`/`warning` 字段，在状态区显示；配置面板的"当前方式状态"区也展示这些信息
- **Manual cookie guide 增强**：在 `SHODAN_COOKIE_MANUAL_GUIDE` 和 `FOFA_COOKIE_MANUAL_GUIDE` 中明确告诉用户哪些 cookie 字段是必需的（Shodan 必需 `shodan_session`，FOFA 必需 `FOFA_TOKEN`），并说明 `polito` 等偏好 cookie 不能用于登录态
- **手动 cookie 保存后展示 warning**：`ApiCredentialManager.saveCookies` 透传后端返回的 `warning` 字段，UI 显示警告条
- **Sonar 失败信息友好展示**：前端无需改动，后端返回的错误信息会通过现有 `statusEl.innerHTML` 显示

## Impact
- Affected specs: `add-spider-api-key-onboarding`、`add-free-sonar-no-api-source`（行为兼容增强，不破坏现有接口）
- Affected code:
  - [attack_resources/shared/attack_resource_api.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/attack_resource_api.py) — cookie 自动/手动/测试 3 个路由 + API 测试/保存 2 个路由
  - [attack_resources/shared/spiders/shodan_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py) — `check_api_key` 增强、`_fetch_via_api` 错误捕获
  - [attack_resources/shared/spiders/sonar_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/sonar_spider.py) — 错误信息明确化
  - [static/script.js](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/static/script.js) — fetch 面板常驻配置按钮、ApiCredentialUi 测试结果展示、guide 增强
  - 无新增依赖（`browser_cookie3` 已在 requirements.txt 中声明）

## ADDED Requirements

### Requirement: browser_cookie3 模块缺失友好提示
当用户点击"自动获取 Cookie"时，如果 `browser_cookie3` 模块未安装，系统 SHALL 返回明确的安装指令，而不是把 Python traceback 拼接到错误消息中。

#### Scenario: 模块未安装
- **WHEN** 用户在 Shodan 或 FOFA 凭据面板点击"自动获取 Cookie"
- **AND** 后端 `import browser_cookie3` 抛出 `ModuleNotFoundError`
- **THEN** 接口返回 `{"success": false, "message": "未安装 browser_cookie3 模块，请在服务器上运行: pip install browser_cookie3==0.16.2", "missing_module": true}`
- **AND** 不再返回 `chrome: No module named ...; firefox: No module named ...; edge: No module named ...` 这样的拼接 traceback

#### Scenario: 模块已安装但浏览器未登录
- **WHEN** `browser_cookie3` 已安装
- **AND** 三个浏览器均未找到目标域名的 cookie
- **THEN** 接口返回 `{"success": false, "message": "未能从浏览器自动获取 <source> cookie。请确保已在浏览器中登录 <domain>。"}`
- **AND** 不再附带 traceback 噪声

### Requirement: 手动 Cookie 关键字段校验
保存手动 cookie 时，系统 SHALL 校验是否包含该数据源登录态必需的关键字段，缺失时返回 warning（但仍允许保存）。

#### Scenario: Shodan cookie 缺少 shodan_session
- **WHEN** 用户提交 Shodan 手动 cookie 字符串
- **AND** 解析后的 dict 不包含 `shodan_session` 键
- **THEN** 接口返回 `{"success": true, "warning": "Cookie 已保存，但未检测到 shodan_session 字段。Shodan 登录态依赖该字段，仅提供 polito 等偏好 cookie 无法通过登录态校验。请重新从浏览器 DevTools 复制完整 Cookie 字符串。"}`
- **AND** cookie 仍被写入凭据存储

#### Scenario: FOFA cookie 缺少 FOFA_TOKEN
- **WHEN** 用户提交 FOFA 手动 cookie 字符串
- **AND** 解析后的 dict 不包含 `FOFA_TOKEN` 键
- **THEN** 接口返回 `{"success": true, "warning": "Cookie 已保存，但未检测到 FOFA_TOKEN 字段。FOFA 登录态依赖该字段，请重新从浏览器 DevTools 复制完整 Cookie 字符串。"}`
- **AND** cookie 仍被写入凭据存储

### Requirement: 常驻"重新配置凭据"入口
IP 资源获取面板 SHALL 在数据源已配置时也显示"重新配置凭据"按钮，让用户随时更换 API key 或 cookie。

#### Scenario: 数据源已配置
- **WHEN** 用户在 IP 资源获取面板选择 Shodan 或 FOFA
- **AND** `isSourceConfigured(source) === true`
- **THEN** 面板显示协议选择 + 结果数量限制 + 「重新配置凭据」按钮（次要按钮样式）
- **AND** 点击「重新配置凭据」按钮调用 `ApiCredentialUi.open(source)` 打开凭据配置面板

#### Scenario: 数据源未配置
- **WHEN** `isSourceConfigured(source) === false`
- **THEN** 维持现有的红色警告 + 「立即配置」按钮行为不变

### Requirement: Shodan API 测试展示 credits/plan
测试 Shodan API key 时，系统 SHALL 返回账号的 `query_credits`、`scan_credits`、`plan` 字段，并在 `query_credits <= 0` 时附 warning。

#### Scenario: API 有效且有搜索额度
- **WHEN** 用户提交的 Shodan API key 通过 `/account/profile` 验证
- **AND** `query_credits > 0`
- **THEN** 接口返回 `{"success": true, "valid": true, "user": "<email>", "query_credits": <int>, "scan_credits": <int>, "plan": "<string>"}`
- **AND** 不附 warning

#### Scenario: API 有效但无搜索额度
- **WHEN** API key 通过 `/account/profile` 验证
- **AND** `query_credits == 0`
- **THEN** 接口返回 `{"success": true, "valid": true, "user": "<email>", "query_credits": 0, "scan_credits": <int>, "plan": "free", "warning": "API 有效但无搜索额度（query_credits=0）。免费账号通常无法使用搜索 API，需购买付费 plan 或改用 Cookie 模式。"}`

### Requirement: Shodan API 搜索错误信息明确化
Shodan 搜索 API 调用失败时，系统 SHALL 从 HTTP 响应体中提取具体错误原因，而非仅返回 status code。

#### Scenario: query credits 耗尽
- **WHEN** `fetch()` 调用搜索 API 返回非 2xx
- **AND** 响应 JSON 含 `error` 字段
- **THEN** 该 query 的 `error` 字段值包含具体错误（如 `query credits exhausted`），而非仅 `403 Client Error`

## MODIFIED Requirements

### Requirement: Sonar 数据集下载失败错误信息
Sonar 爬虫在 Rapid7 商业化 gating 场景下 SHALL 返回明确的失败原因，区分"gating"与"未找到数据集"。

#### Scenario: 服务端返回 HTML（商业化 gating）
- **WHEN** SonarSpider 下载 .csv.gz 时响应体不是 gzip magic
- **AND** 响应内容看起来是 HTML（含 `<html` 或 `login`）
- **THEN** 该 query 的 `error` 字段值为 `"Rapid7 OpenData 已商业化，公开下载受限（服务端返回登录页而非数据文件）。请改用 Shodan 或 FOFA 数据源。"`

#### Scenario: 列表页未匹配到候选文件
- **WHEN** listing 页解析后 `matched` 列表为空
- **THEN** 该 query 的 `error` 字段值保持现有的 `"未找到 <query_name> 对应的 Sonar 数据集文件"` 不变

### Requirement: Manual Cookie 配置 guide 增强
SHODAN_COOKIE_MANUAL_GUIDE 和 FOFA_COOKIE_MANUAL_GUIDE SHALL 明确告知用户哪些 cookie 字段是登录态必需的，避免用户误以为任何 cookie 都能用于登录态校验。

#### Scenario: 用户查看 Shodan 手动 cookie guide
- **THEN** guide 列表中至少包含一条说明：「必需字段：`shodan_session` 和 `shodan_session.sig`。仅复制 `polito` 等偏好 cookie 无法通过登录态校验」
- **AND** 保留现有「按 F12 打开开发者工具 → Network → Cookie 字段」的操作步骤

#### Scenario: 用户查看 FOFA 手动 cookie guide
- **THEN** guide 列表中至少包含一条说明：「必需字段：`FOFA_TOKEN`。请确保复制的 Cookie 字符串包含该字段」
- **AND** 保留现有 Cloudflare 风险提示

## REMOVED Requirements
无。
