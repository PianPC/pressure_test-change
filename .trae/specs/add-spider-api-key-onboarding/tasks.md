# Tasks

- [x] Task 1: 创建凭据持久化存储层
  - [x] SubTask 1.1: 新建 `attack_resources/shared/credential_store.py`，实现 `load_credentials()` / `get_credentials(source)` / `save_credentials(source, data)` / `clear_credentials(source)` 四个函数
  - [x] SubTask 1.2: 凭据文件路径为 `attack_resources/shared/api_credentials.json`，文件不存在时读取返回 `None`，不抛异常
  - [x] SubTask 1.3: `save_credentials` 写入时合并已有内容（不清空其他 source），并写入 `updated_at` ISO 时间戳
  - [x] SubTask 1.4: 在 `.gitignore` 末尾追加 `attack_resources/shared/api_credentials.json`

- [x] Task 2: 改造 Spider 支持凭据热加载
  - [x] SubTask 2.1: 修改 `attack_resources/shared/spiders/shodan_spider.py`：`__init__` 不再从 `SPIDER_CONFIG` 读 `api_key`，改为在 `fetch()` 与 `check_api_key()` 入口处调用 `credential_store.get_credentials("shodan")` 获取
  - [x] SubTask 2.2: 修改 `attack_resources/shared/spiders/fofa_spider.py`：`__init__` 不再从 `SPIDER_CONFIG` 读 `email`/`key`，改为在 `fetch()` 与 `check_credentials()` 入口处调用 `credential_store.get_credentials("fofa")`
  - [x] SubTask 2.3: 修改 `check_api_key()` / `check_credentials()` 支持传入临时凭据参数（用于 `/test` 端点不保存直接测试）

- [x] Task 3: 新增后端凭据 API 路由
  - [x] SubTask 3.1: 在 `attack_resource_api.py` 新增 `GET /api/attack-resource/credentials` 路由，返回各 source 的 `configured` + `updated_at`（不返回明文凭据）
  - [x] SubTask 3.2: 新增 `POST /api/attack-resource/credentials/<source>` 路由，校验必填字段（shodan: api_key；fofa: email, key），保存后调用对应 `check_*` 返回 `valid`/`error`/`user`
  - [x] SubTask 3.3: 新增 `DELETE /api/attack-resource/credentials/<source>` 路由，幂等清除
  - [x] SubTask 3.4: 新增 `POST /api/attack-resource/credentials/<source>/test` 路由，仅用请求体中的凭据调用 `check_*`，不写入文件
  - [x] SubTask 3.5: 未知 source 返回 400；缺少必填字段返回 400

- [x] Task 4: 前端新增 `ApiCredentialManager` 模块
  - [x] SubTask 4.1: 在 `static/script.js` 中新增 IIFE `ApiCredentialManager`，导出 `getCredentialsStatus()` / `saveCredentials(source, data)` / `testCredentials(source, data)` / `clearCredentials(source)` 四个异步函数
  - [x] SubSubtask 4.1.1: 所有函数使用 `getApiUrl('/credentials...')` 拼接路径
  - [x] SubTask 4.2: 在 `templates/index.html` 中新增 `#apiCredentialModal` 节点（参照 `#ipResourceFetchModal` 结构），含 source 选择器、引导面板、输入表单、操作按钮、状态文本区

- [x] Task 5: 实现凭据配置 Modal 与分步引导 UI
  - [x] SubTask 5.1: 在 `#apiCredentialModal` 内为 Shodan 渲染 6 步引导（含外链 https://account.shodan.io/register 和 https://account.shodan.io），1 个 API Key 输入框（password + 显示/隐藏切换）
  - [x] SubTask 5.2: 为 FOFA 渲染 6 步引导（含外链 https://fofa.info/ 和 https://fofa.info/userInfo），Email + API Key 两个输入框
  - [x] SubTask 5.3: 实现「测试连接」按钮 → 调用 `testCredentials` → 在 `#apiCredentialStatus` 显示绿色成功/红色失败
  - [x] SubTask 5.4: 实现「保存」按钮 → 调用 `saveCredentials` → 根据 `valid` 显示绿色或橙色提示
  - [x] SubTask 5.5: 实现「清除」按钮 → 调用 `clearCredentials`（仅在已配置时显示该按钮）
  - [x] SubTask 5.6: 关闭 Modal 时若凭据刚保存成功，触发 Fetch Modal 状态刷新

- [x] Task 6: 改造 Fetch Modal 集成凭据状态
  - [x] SubTask 6.1: 修改 `templates/index.html` 中 `#ipResourceFetchSource` 选项文本为可动态更新（保留 `value` 不变）
  - [x] SubTask 6.2: 在 `static/script.js` 的 `IPResourceUi.openFetchModal()` 中调用 `ApiCredentialManager.getCredentialsStatus()`，根据状态更新 Shodan/FOFA 选项文本为 "(已配置)" / "(未配置)"
  - [x] SubTask 6.3: 在 `updateFetchParams()` 中，若选中 Shodan/FOFA 且未配置，则在 `#ipResourceFetchParams` 顶部渲染红色告警条 + 「立即配置」按钮，并 `disabled` `#ipResourceFetchStart`
  - [x] SubTask 6.4: 实现「立即配置」按钮 → 打开 `#apiCredentialModal` 并预选当前 source
  - [x] SubTask 6.5: 已配置时移除告警条、恢复按钮可点

- [x] Task 7: 首次启动引导提示
  - [x] SubTask 7.1: 在 `#ipResourceFetchModal` 顶部预留 `#ipResourceFetchOnboardingTip` 容器（默认隐藏）
  - [x] SubTask 7.2: 在 `openFetchModal()` 中，若两个 source 均未配置且本次会话未关闭过该提示，则展示提示条 + 「去配置」按钮
  - [x] SubTask 7.3: 实现关闭按钮 → 隐藏提示条并设置 `sessionStorage` 标记，本次会话不再显示

- [x] Task 8: 端到端验证
  - [x] SubTask 8.1: 启动后端，验证 GET `/credentials` 在无文件时返回 `{configured: false}`
  - [x] SubTask 8.2: 验证 POST `/credentials/shodan` 保存无效 key 时仍写入文件并返回 `valid: false`
  - [x] SubSubtask 8.2.1: 验证 GET `/credentials` 此时返回 `configured: true`
  - [x] SubTask 8.3: 验证 DELETE `/credentials/shodan` 清除后 `configured` 回到 `false`
  - [x] SubTask 8.4: 验证 POST `/credentials/fofa` 缺 `key` 字段时返回 400
  - [x] SubTask 8.5: 验证 POST `/credentials/shodan/test` 不修改凭据文件
  - [x] SubTask 8.6: 验证 `api_credentials.json` 不出现在 `git status` 中
  - [ ] SubTask 8.7: 浏览器手动验证：新用户打开 Fetch Modal → 看到 Shodan/FOFA "(未配置)" → 选中 → 看到告警条 → 点击「立即配置」→ 看到分步引导 → 填写 → 测试 → 保存 → 返回 Fetch Modal 看到 "(已配置)" 且按钮可点（需用户在浏览器实际操作）

# Task Dependencies

- Task 2 依赖 Task 1（Spider 改造依赖 credential_store）
- Task 3 依赖 Task 2（API 路由调用 Spider 的 `check_*` 方法）
- Task 5 依赖 Task 4（Modal UI 实现依赖 ApiCredentialManager 模块）
- Task 6 依赖 Task 5（Fetch Modal 集成依赖凭据 Modal 可用）
- Task 7 依赖 Task 6（首次提示依赖 Fetch Modal 状态刷新逻辑）
- Task 8 依赖 Task 1-7 全部完成
- Task 1 与 Task 4 可并行（无依赖）
