# Checklist

## 后端凭据存储
- [x] `attack_resources/shared/credential_store.py` 存在并实现 `load_credentials` / `get_credentials` / `save_credentials` / `clear_credentials` 四个函数
- [x] `api_credentials.json` 不存在时 `load_credentials()` 返回 `{"shodan": None, "fofa": None}`，不抛异常
- [x] `save_credentials("shodan", {"api_key": "X"})` 后 `get_credentials("fofa")` 仍返回原值（不影响其他 source）
- [x] `save_credentials` 自动写入 `updated_at` ISO8601 时间戳
- [x] `clear_credentials` 幂等：清除不存在的 source 不报错
- [x] `.gitignore` 包含 `attack_resources/shared/api_credentials.json`

## Spider 热加载
- [x] `ShodanSpider.fetch()` 入口处从 `credential_store.get_credentials("shodan")` 读取 api_key，不再使用构造时缓存的值
- [x] `FOFASpider.fetch()` 入口处从 `credential_store.get_credentials("fofa")` 读取 email+key
- [x] 保存新凭据后立即调用 `fetch()` 使用新凭据（无需重启）（E2E 测试 6 已验证：保存 invalid_key_12345 后 spider 立即用该 key 发起 Shodan API 请求并返回 401）
- [x] 清除凭据后 `fetch()` 返回 `{"success": False, "error": "...not configured"}`
- [x] `check_api_key()` / `check_credentials()` 支持传入临时凭据参数

## 后端 API 路由
- [x] `GET /api/attack-resource/credentials` 返回每个 source 的 `{configured, updated_at}`，不含明文凭据
- [x] `POST /api/attack-resource/credentials/shodan` 接受 `{api_key}`，保存并返回 `{success, valid, user?, error?}`
- [x] `POST /api/attack-resource/credentials/fofa` 接受 `{email, key}`，保存并返回测试结果
- [x] 缺少必填字段返回 400 + 错误消息
- [x] 未知 source 返回 400
- [x] `POST /api/attack-resource/credentials/<source>/test` 不修改凭据文件
- [x] `DELETE /api/attack-resource/credentials/<source>` 幂等清除

## 前端 ApiCredentialManager
- [x] `static/script.js` 新增 `ApiCredentialManager` 模块导出 4 个异步函数
- [x] 所有函数通过 `getApiUrl('/credentials...')` 拼接路径
- [x] 函数返回 Promise 且不抛未捕获异常（错误以 `{success: false}` 形式返回）

## API 凭据配置 Modal
- [x] `templates/index.html` 包含 `#apiCredentialModal` 节点
- [x] Modal 内有 source 选择器（Shodan / FOFA）
- [x] Shodan 选中时显示 6 步引导，含外链 https://account.shodan.io/register
- [x] FOFA 选中时显示 6 步引导，含外链 https://fofa.info/userInfo
- [x] Shodan 表单含 1 个 API Key 输入框（type=password + 显示/隐藏切换）
- [x] FOFA 表单含 Email 和 API Key 两个输入框
- [x] 「测试连接」按钮调用 `/test` 端点，结果展示在 `#apiCredentialStatus`
- [x] 「保存」按钮调用 POST `/credentials/<source>`
- [x] 「清除」按钮仅在已配置时显示，调用 DELETE
- [x] 保存成功后关闭 Modal 触发 Fetch Modal 状态刷新
- [x] 测试失败时显示橙色提示但凭据已写入（`configured` 仍更新为 true）（E2E 测试 6/7 已验证后端行为：invalid key 仍写入，GET 返回 configured=true；前端橙色提示逻辑已实现）

## Fetch Modal 集成
- [x] `#ipResourceFetchSource` 选项文本由 JS 动态更新为 "(已配置)" / "(未配置)"
- [x] 打开 Fetch Modal 时调用 `getCredentialsStatus()` 刷新徽标
- [x] 选中 Shodan/FOFA 且未配置时显示红色告警条 + 「立即配置」按钮
- [x] 未配置时 `#ipResourceFetchStart` 按钮 `disabled` 并视觉置灰
- [x] 「立即配置」按钮打开 `#apiCredentialModal` 并预选当前 source
- [x] 已配置时不显示告警条，按钮可点

## 首次启动提示
- [x] `#ipResourceFetchOnboardingTip` 容器存在于 Fetch Modal 顶部
- [x] 两 source 均未配置且会话内未关闭过提示时显示
- [x] 关闭后本次会话不再显示（使用 sessionStorage）
- [x] 任一 source 已配置时不显示

## 端到端验证
- [x] 启动后端，GET `/credentials` 在无文件时返回 `{configured: false}`（Flask test client 验证通过）
- [x] POST `/credentials/shodan` 保存无效 key 仍写入并返回 `valid: false`（实际请求 Shodan 返回 401，凭据已写入文件）
- [x] DELETE `/credentials/shodan` 后 `configured` 回到 `false`（幂等清除验证通过）
- [x] POST `/credentials/fofa` 缺 `key` 返回 400（字段校验验证通过，缺 email / 缺 key 均返回 400）
- [x] POST `/credentials/shodan/test` 不修改凭据文件（前后文件内容对比验证通过）
- [x] `git status` 不显示 `api_credentials.json`（已 gitignore）
- [ ] 浏览器：新用户流程完整可走通（未配置→引导→填写→测试→保存→已配置→可获取）（需用户在浏览器手动验证）
