# Spider 网页爬取 0 结果与误判修复 Spec

## Why
用户实测发现：Shodan/FOFA Cookie 配置显示"成功"且测试通过，但实际搜索返回 0 个 IP；FOFA 被 Cloudflare 拦截；Rapid7 Sonar 连接被重置。根本原因是：

1. **`check_web_cookies` 误判**：当前只检查页面中是否含 IP，但 Shodan/FOFA 搜索页本身就有 IP（侧边栏推荐、热门搜索等），即使未登录或搜索结果为空也会判定为"有效"
2. **网页爬取 0 结果无调试信息**：当 `_fetch_via_web` 提取到 0 个 IP 时，仍返回 `success: true`，用户无法知道为什么失败
3. **HTML 选择器单一**：仅依赖 `a[href^='/host/']`（Shodan）和 `a` 标签文本（FOFA），网站改版后易失效
4. **FOFA Cloudflare 不可绕过**：FOFA Cloudflare 防护严格，Cookie 模式基本不可用，需要在 guide 中加强警示
5. **Sonar 网络问题无重试**：`ConnectionResetError` 是网络层瞬时问题，应自动重试

## What Changes

### 后端
- **`check_web_cookies` 严格化**：不再只看 IP 数量，改为检查搜索结果容器（Shodan 检查 `div.search-result` 或类似容器，FOFA 检查 `div.list_module` 或类似容器）；若没有结果容器但页面含 IP，返回 `valid: true` 但 `warning: 检测到页面含 IP 但未找到搜索结果容器，可能登录态受限`
- **`_fetch_via_web` 0 结果时返回 warning + 调试信息**：当 ips 为空时，不写空文件，而是在该 query 的结果中加 `error` 字段（含 status_code、html_length、是否含登录/Cloudflare/JS challenge 标志），并跳过文件写入
- **Shodan HTML 选择器扩展**：除了 `a[href^='/host/']`，增加 `div.search-result`、`div.result`、`[data-ip]` 等选择器；同时检测"Upgrade your account"、"subscription" 等免费账号限制标志
- **FOFA HTML 选择器扩展**：除了 `a` 标签文本，增加 `span.ip`、`div.r_item`、`a.target` 等选择器
- **Sonar 重试机制**：`fetch` 中对 `requests.exceptions.ConnectionError`（含 `ConnectionResetError`）自动重试最多 3 次，间隔 2/4/6 秒；最终失败时返回友好错误信息（可能是网络问题或被防火墙拦截，建议检查网络或使用其他数据源）

### 前端
- **fetch 结果展示 0 IP 警告**：当 `result.success === true` 但所有文件 `ip_count === 0` 或全部含 error 时，显示橙色警告而非绿色成功；展示后端返回的调试信息
- **FOFA Cookie guide 加强警示**：在 `FOFA_COOKIE_AUTO_GUIDE` 和 `FOFA_COOKIE_MANUAL_GUIDE` 顶部加红色警告条，说明"FOFA Cloudflare 防护严格，Cookie 模式大概率不可用，建议优先使用 API 密钥"
- **Sonar 失败信息友好展示**：前端无需改动，后端返回的错误信息会通过现有 UI 显示

## Impact
- Affected specs: `fix-spider-credential-fetch-failures`（行为兼容增强）
- Affected code:
  - [attack_resources/shared/spiders/shodan_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py) — `check_web_cookies` 严格化、`_fetch_via_web` 0 结果处理、选择器扩展
  - [attack_resources/shared/spiders/fofa_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py) — 同上
  - [attack_resources/shared/spiders/sonar_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/sonar_spider.py) — 重试机制
  - [static/script.js](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/static/script.js) — fetch 结果 0 IP 警告、FOFA guide 警示

## ADDED Requirements

### Requirement: check_web_cookies 严格化
`check_web_cookies` SHALL 不再仅根据页面是否含 IP 判定有效性，而是检查是否含搜索结果容器。

#### Scenario: Shodan 登录态有效且有搜索结果
- **WHEN** 访问 Shodan 搜索页返回 200
- **AND** HTML 含 `div.search-result` 或类似搜索结果容器
- **THEN** 返回 `{"valid": true, "ip_count": <int>, "result_containers": <int>}`

#### Scenario: Shodan 登录态有效但搜索结果为空（免费账号受限）
- **WHEN** 访问 Shodan 搜索页返回 200
- **AND** HTML 不含搜索结果容器
- **AND** 页面含 "upgrade"、"subscription"、"credits" 等限制标志
- **THEN** 返回 `{"valid": true, "ip_count": 0, "result_containers": 0, "warning": "登录态有效但搜索结果为空，可能是免费账号受限。Shodan 免费账号网页搜索也受 query credits 限制，建议购买订阅或改用其他数据源。"}`

#### Scenario: Shodan 未登录
- **WHEN** 访问 Shodan 搜索页被重定向到登录页
- **OR** HTML 含登录表单特征（`<form` + `login` 或 `sign in`）
- **THEN** 返回 `{"valid": false, "error": "Cookie 登录态已过期，请重新获取 Cookie"}`

### Requirement: _fetch_via_web 0 结果时返回调试信息
当网页爬取提取到 0 个 IP 时，SHALL NOT 写入空文件，而是返回 error 字段含调试信息。

#### Scenario: Shodan 网页爬取 0 IP
- **WHEN** `_fetch_via_web` 提取到 0 个 IP
- **THEN** 不写入文件
- **AND** 在该 query 的结果中加 `error` 字段，值含：`status_code`、`html_length`、是否含登录/Cloudflare/subscription 标志
- **AND** 示例：`"error": "网页爬取提取到 0 个 IP（status=200, html_length=45000, 含 subscription 标志，可能是免费账号受限）。建议改用 API 密钥或检查 Cookie 登录态。"`

#### Scenario: FOFA 网页爬取 0 IP
- **WHEN** FOFA `_fetch_via_web` 提取到 0 个 IP
- **THEN** 同上处理，不写空文件，返回 error 含调试信息

### Requirement: Sonar 网络重试机制
Sonar 爬虫 SHALL 对网络层错误自动重试，提高可用性。

#### Scenario: ConnectionResetError 自动重试
- **WHEN** `fetch` 调用 `requests.get` 抛出 `ConnectionError`（含 `ConnectionResetError`）
- **THEN** 自动重试最多 3 次，间隔 2/4/6 秒
- **AND** 每次重试在日志中记录

#### Scenario: 重试全部失败
- **WHEN** 3 次重试均失败
- **THEN** 返回 `{"success": false, "error": "无法连接 Rapid7 OpenData 服务器（多次重试失败，最后错误: <详情>）。可能是网络问题或被防火墙拦截，建议检查网络或改用 Shodan/FOFA 数据源。"}`

### Requirement: fetch 结果 0 IP 警告展示
前端 SHALL 在 fetch 结果全部为 0 IP 或全部含 error 时显示橙色警告，而非绿色成功。

#### Scenario: 所有 query 返回 0 IP
- **WHEN** `result.success === true`
- **AND** 所有 files 的 `ip_count === 0` 或含 error
- **THEN** 状态显示橙色警告：「获取完成，但未提取到任何 IP（可能是免费账号受限或网站改版），详情见控制台」
- **AND** 在下方展示每个 query 的 error 信息

#### Scenario: 部分 query 成功
- **WHEN** 部分 query 成功（ip_count > 0），部分失败
- **THEN** 显示黄色提示：「获取完成，成功 N/M 个资源（部分失败）」

## MODIFIED Requirements

### Requirement: FOFA Cookie guide 加强 Cloudflare 警示
FOFA_COOKIE_AUTO_GUIDE 和 FOFA_COOKIE_MANUAL_GUIDE SHALL 在首条加红色警告，明确告知 Cookie 模式大概率不可用。

#### Scenario: 用户查看 FOFA Cookie guide
- **THEN** guide 列表首条为：`<strong style="color:#ff6b6b;">⚠️ 警告：FOFA 使用 Cloudflare 严格防护，Cookie 模式大概率被拦截。如有可能，请优先使用 API 密钥（需付费账号）。</strong>`
- **AND** 保留现有操作步骤

### Requirement: Shodan HTML 选择器扩展
Shodan `_fetch_via_web` SHALL 支持多种 HTML 选择器，提高网站改版鲁棒性。

#### Scenario: 主选择器失效但兜底选择器命中
- **WHEN** `a[href^='/host/']` 选择器未匹配到元素
- **AND** `div.search-result`、`[data-ip]` 等兜底选择器匹配到元素
- **THEN** 从兜底选择器提取 IP
- **AND** 正则兜底仍保留

## REMOVED Requirements
无。
