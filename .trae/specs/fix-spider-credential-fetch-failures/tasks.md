# Tasks

- [x] Task 1: 后端 - `browser_cookie3` 模块缺失友好提示
  - [x] 修改 `attack_resource_api.py` 的 `auto_extract_cookies_route`：在尝试 `import browser_cookie3` 时单独捕获 `ModuleNotFoundError`，立即返回 `{"success": false, "message": "未安装 browser_cookie3 模块，请在服务器上运行: pip install browser_cookie3==0.16.2", "missing_module": true}`
  - [x] 模块已安装但无 cookie 的兜底消息保持现有「请确保已在浏览器中登录 <domain>」，但不再附带每个浏览器的 traceback

- [x] Task 2: 后端 - 手动 Cookie 关键字段校验
  - [x] 在 `attack_resource_api.py` 新增 `_REQUIRED_COOKIE_FIELDS` 映射：`{"shodan": "shodan_session", "fofa": "FOFA_TOKEN"}`
  - [x] 修改 `save_cookies_route`：保存成功后检查 dict 是否包含必需字段，缺失时在响应中追加 `warning` 字段
  - [x] 保留现有 `success: true` 行为，cookie 仍写入存储

- [x] Task 3: 后端 - Shodan API 测试返回 credits/plan
  - [x] 修改 `shodan_spider.py` 的 `check_api_key`：从 `/account/profile` 响应中读取 `query_credits`、`scan_credits`、`plan`，加入返回 dict
  - [x] 当 `query_credits <= 0` 时，在返回 dict 中追加 `warning` 字段，文案见 spec
  - [x] 修改 `attack_resource_api.py` 的 `test_credentials_route` 和 `save_credentials_route`：透传 `query_credits`/`scan_credits`/`plan`/`warning` 字段

- [x] Task 4: 后端 - Shodan API 搜索错误信息增强
  - [x] 修改 `shodan_spider.py` 的 `_fetch_via_api`：捕获 `requests.HTTPError`，从 `response.json()` 提取 `error` 字段，组装为更友好的错误消息
  - [x] 兜底：响应体非 JSON 时退回 `str(e)`

- [x] Task 5: 后端 - Sonar 错误信息明确化
  - [x] 修改 `sonar_spider.py` 的 `fetch`：在响应体不是 gzip magic 的分支中，检测内容是否含 `<html` 或 `login`，是则返回明确的商业化 gating 消息
  - [x] 保留现有"未找到数据集文件"分支不变

- [x] Task 6: 前端 - 常驻"重新配置凭据"入口
  - [x] 修改 `static/script.js` 第 994-1025 行的已配置分支：在协议选择 + limit 输入下方追加「重新配置凭据」按钮（次要按钮样式，与"立即配置"按钮区分）
  - [x] 按钮点击调用 `ApiCredentialUi.open(source)`
  - [x] 未配置分支保持不变

- [x] Task 7: 前端 - API 测试结果展示 credits/plan
  - [x] 修改 `ApiCredentialUi.testConnection`：从后端响应中读取 `query_credits`/`scan_credits`/`plan`/`warning`，在 `#apiCredentialStatus` 中以友好格式展示
  - [x] 当 `warning` 存在时，用警告色（橙色）单独展示一行
  - [x] 修改 `renderCurrentStatus`：如果 `credentialStatusCache` 中有 credits 信息也一并展示

- [x] Task 8: 前端 - Manual Cookie guide 增强
  - [x] 修改 `SHODAN_COOKIE_MANUAL_GUIDE`：新增一条「必需字段：`shodan_session` 和 `shodan_session.sig`。仅复制 `polito` 等偏好 cookie 无法通过登录态校验」
  - [x] 修改 `FOFA_COOKIE_MANUAL_GUIDE`：新增一条「必需字段：`FOFA_TOKEN`。请确保复制的 Cookie 字符串包含该字段」
  - [x] 修改 `ApiCredentialManager.saveCookies`：透传后端返回的 `warning` 字段，由调用方决定如何展示

- [x] Task 9: 验证 - 端到端场景检查
  - [x] 未安装 browser_cookie3 时点击"自动获取 Cookie"，确认返回安装指令
  - [x] 提交只含 `polito` 的 Shodan cookie，确认返回 warning 但保存成功
  - [x] Shodan API 配置后点击"测试连接"，确认显示 query_credits/plan
  - [x] 配置成功后在 fetch 面板确认看到「重新配置凭据」按钮
  - [x] Sonar 失败时确认错误信息明确提到"商业化"

# Task Dependencies
- Task 3 必须先于 Task 7（前端要展示后端返回的 credits 字段）
- Task 2 必须先于 Task 8（前端要透传后端返回的 warning）
- 其余任务可并行
