# 迁移 FOFA Vue SSR 爬虫方案 Spec

## Why
当前系统的 FOFA 网页爬取（`_fetch_via_web`）使用 BeautifulSoup 解析 HTML 元素（`a.target`、`span.ip` 等），但 FOFA 使用 Nuxt.js 服务端渲染，搜索结果数据被序列化为 JSON 嵌入 HTML `<script>` 标签（Vue 3 ShallowReactive 格式），HTML 元素解析不可靠且易受网站改版影响。

参考实现 `ip_collector/collectors/fofa_scraper.py` 已成功验证一套绕过 Cloudflare 和 API 限制的方案，核心是：解析 Vue SSR 序列化数据 + 多查询变体策略 + 登录态关键词检测 + 随机 UA 限速。将该方案迁移到本系统可显著提升 FOFA Cookie 模式的成功率和 IP 获取量。

## What Changes

### 后端
- **Vue SSR 数据解析**（核心）：在 `fofa_spider.py` 的 `_fetch_via_web` 中新增 Vue SSR 数据解析作为首选方法，从 HTML `<script>` 标签提取 `[["ShallowReactive",...]]` 格式的 JSON，解析 ShallowReactive 引用结构提取 IP；BeautifulSoup 元素解析降级为兜底
- **多查询变体策略**：新增 `_generate_query_variants` 方法，按国家/地区（US/CN/JP/DE 等）生成查询变体，每个变体返回不同 IP 子集，累计获取更多 IP（解决 FOFA SSR 只返回第一页约 10 条的限制）
- **登录态关键词检测**：升级 `check_web_cookies`，访问首页 `https://fofa.info/` 检测「退出」「logout」「个人中心」「我的资产」「会员中心」等关键词判定登录态，比检测 IP 可靠
- **随机 UA + 限速**：新增 USER_AGENTS 列表，每次请求随机切换 UA；请求间随机延迟 3-8 秒（可配置）
- **Cookie 必需字段修正**：`_REQUIRED_COOKIE_FIELDS` 中 fofa 的必需字段从 `FOFA_TOKEN`（大写，错误）改为 `fofa_token`（小写，正确，与参考实现一致）
- **总数提取**：新增 `_get_total_count` 从 Vue 数据中提取搜索结果总数，用于日志和 UI 展示
- **lxml 解析器**：`requirements.txt` 新增 `lxml` 依赖（BeautifulSoup 使用 lxml 解析器，比 html.parser 快且容错好）

### 前端
- **FOFA Cookie guide 修正**：`FOFA_COOKIE_MANUAL_GUIDE` 中必需字段说明从 `FOFA_TOKEN` 改为 `fofa_token`
- **FOFA Cookie guide 优化**：移除"Cookie 模式大概率被拦截"的过度悲观警告（参考实现证明 Cookie 模式可用），改为中性提示"FOFA 使用服务端渲染，Cookie 模式可获取数据但受 web_query 配额限制"

## Impact
- Affected specs: `fix-spider-credential-fetch-failures`（Cookie 必需字段修正）、`fix-spider-web-scrape-zero-results`（Vue SSR 解析替代元素解析）
- Affected code:
  - [attack_resources/shared/spiders/fofa_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py) — Vue SSR 解析、多查询变体、登录态检测、随机 UA 限速
  - [attack_resources/shared/attack_resource_api.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/attack_resource_api.py) — `_REQUIRED_COOKIE_FIELDS` fofa 字段修正
  - [requirements.txt](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/requirements.txt) — 新增 lxml
  - [static/script.js](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/static/script.js) — FOFA Cookie guide 文案修正

## ADDED Requirements

### Requirement: Vue SSR 数据解析
`_fetch_via_web` SHALL 优先从 HTML `<script>` 标签中解析 Vue/Nuxt.js 服务端渲染的序列化数据提取 IP，元素解析降级为兜底。

#### Scenario: Vue SSR 数据解析成功
- **WHEN** FOFA 搜索页返回 200
- **AND** HTML 含 `<script>` 标签内嵌 `[["ShallowReactive",...]]` 格式 JSON
- **THEN** 用正则提取该 JSON，`json.loads` 解析为数组
- **AND** 遍历数组找含 `assets` 和 `page` 字段的 dict
- **AND** 解析 `assets` 引用（数字索引指向数组元素）得到资产列表
- **AND** 每个资产 dict 含 `ip` 字段（也是引用），解析得到 IP 字符串
- **AND** 用正则验证 IP 格式后加入结果列表

#### Scenario: Vue SSR 数据解析失败时兜底
- **WHEN** HTML 不含 Vue SSR 数据
- **OR** 解析过程中抛出异常
- **THEN** 降级到现有的 BeautifulSoup 元素解析（`a.target`、`span.ip` 等）
- **AND** 最终正则全文兜底

### Requirement: 多查询变体策略
`_fetch_via_web` SHALL 通过生成多个查询变体（按国家/地区过滤）累计获取更多 IP，解决 FOFA SSR 只返回第一页约 10 条的限制。

#### Scenario: 生成查询变体
- **WHEN** 调用 `_fetch_via_web` 处理一个 query_name（如 dns）
- **THEN** 生成查询变体列表，包含：
  - 原始查询（如 `port="53" && protocol="dns"`）
  - 按国家过滤的变体：`<原始查询> && country="US"`、`country="CN"`、`country="JP"` 等（最多 max_variants 个）
- **AND** 变体数量受 limit 参数约束（limit / 10 向上取整，最少 3，最多 18）

#### Scenario: 累计去重
- **WHEN** 每个变体查询返回 IP 列表
- **THEN** 跨变体去重，累计合并
- **AND** 当累计 IP 数达到 limit 时提前终止

### Requirement: 登录态关键词检测
`check_web_cookies` SHALL 访问 FOFA 首页检测登录态关键词，而非仅检测页面是否含 IP。

#### Scenario: 登录态有效
- **WHEN** 访问 `https://fofa.info/` 返回 200
- **AND** 页面文本含「退出」「logout」「个人中心」「我的资产」「会员中心」任一关键词
- **THEN** 返回 `{"valid": true, "login_confirmed": true}`

#### Scenario: 登录态失效
- **WHEN** 访问首页返回 200
- **AND** 页面不含上述任何关键词
- **THEN** 返回 `{"valid": false, "error": "Cookie 登录态已过期，请重新获取 Cookie"}`

#### Scenario: Cloudflare 拦截
- **WHEN** 访问首页返回 403/503
- **OR** 页面含 `cf-challenge`/`cloudflare`
- **THEN** 返回 `{"valid": false, "error": "FOFA 被 Cloudflare 拦截，Cookie 模式不可用，建议使用 API 密钥"}`

### Requirement: 随机 User-Agent 与限速
`_fetch_via_web` SHALL 每次请求随机切换 User-Agent，并在请求间加入随机延迟，降低被封风险。

#### Scenario: 随机 UA
- **WHEN** 发起 FOFA 网页请求
- **THEN** 从 USER_AGENTS 列表（至少 5 个常见浏览器 UA）随机选择一个
- **AND** 设置到请求 headers

#### Scenario: 随机延迟
- **WHEN** 连续发起多个变体查询请求
- **THEN** 每个请求间随机延迟 3-8 秒（可配置）

### Requirement: 搜索结果总数提取
`_fetch_via_web` SHALL 从 Vue SSR 数据中提取搜索结果总数，用于日志记录。

#### Scenario: 提取总数
- **WHEN** Vue SSR 数据解析成功
- **AND** 数据中含 `page` 字段，其引用的 dict 含 `total` 字段
- **THEN** 提取 total 值，记录到日志「查询 <variant> 总数 <total>，本页提取 <ip_count> 个 IP」

## MODIFIED Requirements

### Requirement: FOFA Cookie 必需字段
`_REQUIRED_COOKIE_FIELDS` 中 fofa 的必需字段 SHALL 为 `fofa_token`（小写），而非 `FOFA_TOKEN`（大写）。

#### Scenario: FOFA cookie 缺少 fofa_token
- **WHEN** 用户提交 FOFA 手动 cookie 字符串
- **AND** 解析后的 dict 不包含 `fofa_token` 键
- **THEN** 接口返回 `warning` 字段：「Cookie 已保存，但未检测到 fofa_token 字段。FOFA 登录态依赖该字段（JWT 格式），请重新从浏览器 DevTools 复制完整 Cookie 字符串。」
- **AND** cookie 仍被写入凭据存储

### Requirement: FOFA Cookie guide 文案修正
FOFA_COOKIE_AUTO_GUIDE 和 FOFA_COOKIE_MANUAL_GUIDE SHALL 修正必需字段名称，并调整 Cloudflare 警示措辞为中性。

#### Scenario: 用户查看 FOFA 手动 cookie guide
- **THEN** guide 中必需字段说明为 `fofa_token`（小写）
- **AND** 首条警告调整为：「⚠️ 提示：FOFA 使用服务端渲染，Cookie 模式可获取数据但受 web_query 配额限制（免费账号约 300 次/天）。如配额耗尽，请改用 API 密钥或等待次日刷新。」
- **AND** 移除"Cookie 模式大概率被拦截"的过度悲观表述

## REMOVED Requirements
无。
