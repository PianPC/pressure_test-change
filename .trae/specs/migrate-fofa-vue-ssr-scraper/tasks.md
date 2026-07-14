# Tasks

- [x] Task 1: 后端 - 新增 lxml 依赖
  - [x] 在 `requirements.txt` 追加 `lxml>=4.9.0`

- [x] Task 2: 后端 - Vue SSR 数据解析模块
  - [x] 在 `fofa_spider.py` 新增模块级常量 `USER_AGENTS`（至少 5 个常见浏览器 UA）
  - [x] 新增 `_parse_vue_data(html)` 方法：正则提取 `<script>` 内的 `[["ShallowReactive",...]]` JSON，`json.loads` 解析为数组，失败返回 None
  - [x] 新增 `_resolve_vue_ref(data, ref)` 方法：数字索引引用解析
  - [x] 新增 `_parse_ips_from_vue(vue_data)` 方法：遍历找含 `assets` 和 `page` 字段的 dict，解析 assets 引用得到资产列表，每个资产 dict 含 `ip` 字段，解析后用正则验证 IP 格式
  - [x] 新增 `_get_total_count(vue_data)` 方法：从 `page.total` 提取总数

- [x] Task 3: 后端 - 多查询变体策略
  - [x] 新增 `_generate_query_variants(base_query, max_variants)` 方法：生成原始查询 + 按国家过滤的变体（US/CN/JP/DE/GB/FR/BR/IN/KR/RU/CA/AU/IT/ES/NL/SG/HK/TW）
  - [x] max_variants 根据 limit 计算：`max(3, min(18, math.ceil(limit / 10)))`

- [x] Task 4: 后端 - 升级 _fetch_via_web 集成 Vue SSR + 多变体
  - [x] 修改 `_fetch_via_web`：对每个 query_name 生成查询变体列表
  - [x] 每个变体请求 `https://fofa.info/result?qbase64=<base64>&page=1`，随机 UA + 随机延迟 3-8 秒
  - [x] 优先用 `_parse_vue_data` + `_parse_ips_from_vue` 解析 IP；失败时降级到现有 BeautifulSoup 元素解析；最终正则兜底
  - [x] 跨变体去重，累计合并；达到 limit 时提前终止
  - [x] 0 IP 时不写文件，返回 error 含调试信息（保留现有逻辑）
  - [x] 记录日志：每个变体的查询条件、总数、本页 IP 数、新增 IP 数

- [x] Task 5: 后端 - 升级 check_web_cookies 登录态检测
  - [x] 修改 `check_web_cookies`：访问首页 `https://fofa.info/` 检测登录态关键词（「退出」「logout」「个人中心」「我的资产」「会员中心」）
  - [x] Cloudflare 检测保留（403/503/cf-challenge/cloudflare）
  - [x] 登录态有效时，额外用 Vue SSR 解析一个测试查询（如 `ip=1.1.1.1`）检测搜索结果容器，返回 `result_containers` 字段
  - [x] 保留现有的 warning 字段逻辑

- [x] Task 6: 后端 - 修正 Cookie 必需字段
  - [x] 修改 `attack_resource_api.py` 的 `_REQUIRED_COOKIE_FIELDS`：fofa 从 `FOFA_TOKEN` 改为 `fofa_token`
  - [x] 修改 `save_cookies_route` 中 fofa 的 warning 文案：`fofa_token`（JWT 格式）

- [x] Task 7: 前端 - FOFA Cookie guide 文案修正
  - [x] 修改 `FOFA_COOKIE_AUTO_GUIDE` 首条：调整为中性提示「FOFA 使用服务端渲染，Cookie 模式可获取数据但受 web_query 配额限制（免费账号约 300 次/天）」
  - [x] 修改 `FOFA_COOKIE_MANUAL_GUIDE`：必需字段从 `FOFA_TOKEN` 改为 `fofa_token`；首条警告同上调整
  - [x] 移除"Cookie 模式大概率被拦截"的过度悲观表述

- [x] Task 8: 验证 - 端到端场景检查
  - [x] Vue SSR 数据解析：Grep `_parse_vue_data` 和 `ShallowReactive` 在 fofa_spider.py 中
  - [x] 多查询变体：Grep `_generate_query_variants` 和 `country=` 在 fofa_spider.py 中
  - [x] 登录态关键词：Grep `logout` 和 `个人中心` 在 fofa_spider.py 中
  - [x] 随机 UA：Grep `USER_AGENTS` 在 fofa_spider.py 中
  - [x] Cookie 必需字段：Grep `fofa_token` 在 attack_resource_api.py 中（确认不再是 FOFA_TOKEN）
  - [x] lxml 依赖：Grep `lxml` 在 requirements.txt 中
  - [x] 前端 guide：Grep `fofa_token` 在 script.js 中
  - [x] `python -m py_compile` 验证 fofa_spider.py 语法

# Task Dependencies
- Task 2 必须先于 Task 4（Vue 解析方法先实现，再集成到 fetch）
- Task 3 必须先于 Task 4（变体生成先实现，再集成到 fetch）
- Task 6 必须先于 Task 7（后端字段修正后，前端 guide 同步修正）
- 其余任务可并行
