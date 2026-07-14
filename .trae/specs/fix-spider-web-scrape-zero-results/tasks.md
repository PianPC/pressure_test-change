# Tasks

- [x] Task 1: 后端 - Shodan check_web_cookies 严格化
  - [x] 修改 `shodan_spider.py` 的 `check_web_cookies`：除了检测登录态，额外检测搜索结果容器（`div.search-result`、`div.result`、`[data-ip]` 等）
  - [x] 当无结果容器但含 "upgrade"/"subscription"/"credits" 标志时，返回 `warning` 字段说明免费账号受限
  - [x] 返回 dict 新增 `result_containers` 字段（int）

- [x] Task 2: 后端 - FOFA check_web_cookies 严格化
  - [x] 修改 `fofa_spider.py` 的 `check_web_cookies`：检测 FOFA 结果容器（`div.list_module`、`div.r_item`、`a.target` 等）
  - [x] Cloudflare 检测保留，明确告知用户 Cookie 模式不可用

- [x] Task 3: 后端 - Shodan _fetch_via_web 0 结果处理 + 选择器扩展
  - [x] 修改 `shodan_spider.py` 的 `_fetch_via_web`：增加 `div.search-result`、`div.result`、`[data-ip]` 等选择器
  - [x] 当 ips 为空时，不写文件，返回 error 字段含调试信息（status_code、html_length、是否含 subscription/login/cloudflare 标志）
  - [x] 保留原有 `a[href^='/host/']` 选择器作为首选

- [x] Task 4: 后端 - FOFA _fetch_via_web 0 结果处理 + 选择器扩展
  - [x] 修改 `fofa_spider.py` 的 `_fetch_via_web`：增加 `span.ip`、`div.r_item`、`a.target` 等选择器
  - [x] 当 ips 为空时，同 Task 3 处理，返回 error 含调试信息

- [x] Task 5: 后端 - Sonar 重试机制
  - [x] 修改 `sonar_spider.py` 的 `fetch`：对 `requests.exceptions.ConnectionError` 自动重试最多 3 次，间隔 2/4/6 秒（用 `time.sleep`）
  - [x] 重试全部失败时返回友好错误信息（含"可能是网络问题或被防火墙拦截，建议改用 Shodan/FOFA"）
  - [x] 列表页请求和文件下载请求均需重试

- [x] Task 6: 前端 - fetch 结果 0 IP 警告展示
  - [x] 修改 `static/script.js` 的 `startFetch`：当 `result.success === true` 但所有 files 的 `ip_count === 0` 或全部含 error 时，显示橙色警告而非绿色成功
  - [x] 在状态下方展示每个 query 的 error 信息（用 `<details>` 折叠）
  - [x] 部分成功时显示黄色提示

- [x] Task 7: 前端 - FOFA Cookie guide 加强 Cloudflare 警示
  - [x] 修改 `FOFA_COOKIE_AUTO_GUIDE` 和 `FOFA_COOKIE_MANUAL_GUIDE`：在首条加红色警告，说明 Cloudflare 严格防护、Cookie 模式大概率不可用、建议优先用 API

- [x] Task 8: 验证 - 端到端场景检查
  - [x] Shodan check_web_cookies 在登录态有效但无结果容器时返回 warning
  - [x] Shodan _fetch_via_web 在 0 IP 时不写文件，返回 error 含调试信息
  - [x] FOFA _fetch_via_web 同上
  - [x] Sonar ConnectionError 自动重试 3 次
  - [x] 前端在 0 IP 时显示橙色警告
  - [x] FOFA guide 首条含红色 Cloudflare 警告

# Task Dependencies
- Task 1, 2 必须先于 Task 3, 4（check 逻辑先改，fetch 逻辑后改，避免不一致）
- Task 3, 4 必须先于 Task 6（前端要展示后端返回的 error 信息）
- 其余任务可并行
