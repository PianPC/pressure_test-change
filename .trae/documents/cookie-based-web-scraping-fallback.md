# Cookie 模式爬取：无 API 密钥使用 Shodan/FOFA（3 方式并列 + 可更改/可替换配置）

## Summary

为 Shodan/FOFA 重构凭据配置 Modal，明面展示 **3 种配置方式**并列，每种方式有独立详细配置说明、独立测试/保存/清除、独立状态指示。用户可随时**更改、替换、切换**配置：API key 没钱时换一个有钱的 API key、或切到 Cookie；Cookie 过期时重新获取。Spider 按优先级自动选择可用方式（API > Cookie）。

## 用户核心诉求（本次修订重点）

1. **可更改/可替换配置**（两次反馈强调）：
   - 不是一次配置锁死。
   - **API key 可替换**：当前 API key 没钱/失效时，能输入新 API key 覆盖旧的（"更换有钱的 api 来进行爬取"）。
   - Cookie 过期时能重新获取/替换。
   - 能在 3 种方式间切换、共存、独立清除。
2. **3 种方式明面显示**：方式一 API 密钥 / 方式二 Cookie 自动获取 / 方式三 Cookie 手动粘贴，并列展示，不全则保留。
3. **每种方式有详细配置说明**：分步引导（注册→登录→获取→填写→测试→保存/替换），含外链，含"更换/替换"场景说明。

## Current State Analysis

### 现有凭据 Modal 结构（`static/script.js` L224-432 `ApiCredentialUi`）
- 单一 source 选择器（Shodan/FOFA）
- 单一 guide（`SHODAN_GUIDE` 6 步 / `FOFA_GUIDE` 6 步，仅针对 API key）
- 单一 form（Shodan: 1 个 API key 输入框；FOFA: email + key）
- `testConnection()` / `save()` / `clear()` 操作的是 API key 凭据
- `refreshClearButton()` 仅检查 API key 的 `configured` 状态
- **无法配置 Cookie**，无法切换方式，无 Cookie 相关 UI
- **无"替换"UX**：form 打开时为空（后端不返回明文），用户不知道输入新值会覆盖旧值

### 现有后端
- `credential_store.py` L40-66：`save_credentials(source, data)` 执行**整体替换**（`existing[source] = new_entry`，new_entry 仅含传入的 data 字段）。**问题**：若已配置 cookies，调用 save 保存新 api_key 会丢失 cookies。需改为合并写入。
- `attack_resource_api.py` L1623-1701：4 个凭据路由仅处理 API key
  - `GET /credentials`（L1623-1632）：返回 `configured` 仅基于 api_key/email/key 是否非空
  - `POST /credentials/<source>`（L1635-1646）：接收 payload，调 `save_credentials`（整体替换）
  - `DELETE /credentials/<source>`（L1664-1672）：`clear_credentials`
  - `POST /credentials/<source>/test`（L1677-1701）：调 spider 的 `check_api_key`/`check_credentials`

### 现有 Spider
- `shodan_spider.py` L22-105：`fetch()` 仅读 `api_key`，无 cookie 路径
- `fofa_spider.py` L24-101：同上

### 依赖
- `requirements.txt`：仅 `requests==2.34.2`，无 `browser_cookie3`、无 `beautifulsoup4`

## Proposed Changes

### 1. 依赖安装
**文件**：`requirements.txt`
- 追加 `browser_cookie3==0.16.2`
- 追加 `beautifulsoup4==4.12.3`

### 2. 扩展凭据存储支持 cookie + 修复合并写入 ★关键修复★
**文件**：`attack_resources/shared/credential_store.py`

- **修改 `save_credentials(source, data)`（L40-66）**：改为**合并写入**，保留现有字段（如 cookies）。逻辑：
  ```python
  existing_entry = existing.get(source) if isinstance(existing.get(source), dict) else {}
  merged = dict(existing_entry)  # 保留旧字段（如 cookies）
  merged.update(data)            # 用新 data 覆盖/新增
  merged["updated_at"] = datetime.now().isoformat()
  existing[source] = merged
  ```
  - 效果：保存新 api_key 时，若已有 cookies，cookies 保留；反之亦然。
  - 替换 API key：传入 `{api_key: "新key"}` → 合并后旧 api_key 被新值覆盖，cookies 不动。

- 新增 3 个函数：
  - `get_cookies(source) -> dict | None`：从 `get_credentials(source)` 取 `cookies` 字段
  - `save_cookies(source, cookies_dict)`：合并写入 `cookies` 字段（调 `save_credentials(source, {"cookies": cookies_dict})`，复用合并逻辑）
  - `clear_cookies(source)`：读取现有条目，删除 `cookies` 字段，保留 api_key/email/key，写回

### 3. 后端 Cookie API 路由
**文件**：`attack_resources/shared/attack_resource_api.py`（L1701 后追加）
- `GET /credentials/<source>/cookies` → `{success, configured, updated_at}`（不返回 cookie 明文）
- `POST /credentials/<source>/cookies` → 请求体 `{cookie_string}`，解析为 dict，`save_cookies`
- `POST /credentials/<source>/cookies/auto` → `browser_cookie3` 读取目标域名 cookie（shodan→`.shodan.io`，fofa→`.fofa.info`），依次尝试 Chrome/Firefox/Edge，保存并返回 `{success, count}` 或 `{success:false, message}`
- `POST /credentials/<source>/cookies/test` → 用已存 cookie 发网页搜索测试，返回 `{valid, ip_count, error}`
- `DELETE /credentials/<source>/cookies` → `clear_cookies`
- **修改 `GET /credentials`（L1623-1632）**：`configured` 改为 `api_key_configured or cookies_configured`，且额外返回 `api_key_configured` 和 `cookies_configured` 两个子字段，供前端分别显示各方式状态

### 4. Spider 新增网页爬取模式
**文件**：`attack_resources/shared/spiders/shodan_spider.py`
- `fetch()` 入口逻辑改为三段：
  1. 有 `api_key` → 走现有 API 模式（L33-105 不变）
  2. 无 api_key 但有 `cookies` → 调用 `_fetch_via_web(query_names, limit, cookies)`
  3. 都没有 → 返回 `"Shodan 未配置（需 API 密钥或 Cookie，请在配置面板选择一种方式）"`
- 新增 `_fetch_via_web(self, query_names, limit, cookies)`：
  - `requests.Session()` + `session.cookies.update(cookies)` + Chrome UA header
  - URL：`https://www.shodan.io/search?query=<urlencode(query_str)>`
  - 响应含 login/sign in/302 → 登录态失效错误
  - `bs4.BeautifulSoup` 解析 + regex `r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"` 兜底提取 IP
  - 去重、按 limit 截断、写文件（文件头标注 `# Mode: web-cookie`）
- 新增 `check_web_cookies(cookies=None)`：访问 `https://www.shodan.io/` 检查是否跳转登录

**文件**：`attack_resources/shared/spiders/fofa_spider.py`
- 同结构：API 优先 → Cookie 回退 → 错误
- URL：`https://fofa.info/result?qbase64=<base64>`
- **Cloudflare 风险**：检测 `cf-challenge`/403/503 → 返回 `"FOFA 被 Cloudflare 拦截，Cookie 模式可能不可用，建议使用 API 密钥"`
- 新增 `check_web_cookies(cookies=None)`

### 5. 前端重构：3 方式并列配置面板 + 明确替换 UX ★核心改动★
**文件**：`templates/index.html`（`#apiCredentialModal` 内 `.ip-resource-fetch-body` 区域重构）

将现有的单一 guide+form 替换为 **方式选择器 + 3 个方式面板**：

```
┌─ #apiCredentialModal ─────────────────────────┐
│ [Source 选择器: Shodan / FOFA]                 │
│                                                │
│ ┌─ 方式状态总览 ─────────────────────────────┐  │
│ │ 方式一 API密钥: ✅已配置 (点击更换/替换)    │  │
│ │ 方式二 Cookie自动: ❌未配置                 │  │
│ │ 方式三 Cookie手动: ❌未配置                 │  │
│ │ → 当前生效: 方式一                          │  │
│ └────────────────────────────────────────────┘  │
│                                                │
│ [方式选择 Tab: 方式一 | 方式二 | 方式三]        │
│                                                │
│ ┌─ 选中方式的详细引导 + 表单 + 操作按钮 ──────┐  │
│ │ <ol>分步引导（含外链 + 更换场景说明）</ol>  │  │
│ │ <当前状态提示: 已配置/未配置>               │  │
│ │ <输入框>                                    │  │
│ │ [测试] [保存/替换] [清除]                    │  │
│ │ <状态文本>                                   │  │
│ └────────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
```

**文件**：`static/script.js`（`ApiCredentialUi` 模块 L224-432 重构）

#### 5.1 新增 6 套 guide（每套含详细分步说明 + 外链 + 更换场景）
- `SHODAN_API_GUIDE`（现有 6 步 + 追加"更换 API key"说明）：
  - ①-⑥ 现有注册→获取→填写→测试→保存
  - ⑦ **更换场景**："若当前 API key 余额不足或失效，直接在下方输入框填入新的 API key，点击「测试」验证后点击「替换保存」即可覆盖旧 key。无需先清除。"
- `SHODAN_COOKIE_AUTO_GUIDE`：① 在浏览器中访问 https://www.shodan.io 并登录账号 ② 确保登录成功（页面右上角显示用户名）③ 回到本页面点击下方「从浏览器自动获取」按钮 ④ 系统自动读取浏览器中的 Shodan cookie ⑤ 点击「测试 Cookie」验证登录态有效 ⑥ 点击「保存」完成配置。**Cookie 过期后重新执行①-⑥即可替换。**
- `SHODAN_COOKIE_MANUAL_GUIDE`：① 在浏览器中访问 https://www.shodan.io 并登录 ② 按 F12 打开开发者工具，切换到 Network 标签 ③ 刷新页面，在请求列表中点击任意一个请求 ④ 在右侧 Headers 面板找到 Request Headers 下的 Cookie 字段 ⑤ 复制 Cookie 后的完整值（形如 `key1=val1; key2=val2`）⑥ 粘贴到下方输入框，点击「测试」再「保存」。**Cookie 过期后重新粘贴新值即可替换。**
- FOFA 同理 3 套 guide（`FOFA_API_GUIDE` 现有 + 更换说明 / `FOFA_COOKIE_AUTO_GUIDE` / `FOFA_COOKIE_MANUAL_GUIDE`）

#### 5.2 方式选择器 + 状态总览
- 新增 `renderMethodTabs()`：在 Modal 内渲染 3 个 Tab（方式一/二/三），点击切换显示对应 guide + form
- 新增 `renderMethodStatus()`：调用 `getCredentialsStatus()` 获取 `api_key_configured` 和 `cookies_configured`，在 Modal 顶部「方式状态总览」区域显示 3 个方式各自的状态 + 当前生效方式。已配置的方式旁显示「点击更换」提示。

#### 5.3 重构 `renderForm()`：根据当前方式渲染不同表单
- 方式一（API key）：
  - **新增"当前状态"提示行**：若已配置，显示 `当前已配置 API 密钥（••••••••<末4位>）。输入新值将替换旧值。`（后端返回 masked 提示，不返回明文）
  - 现有 API key 输入框（Shodan 1 个 / FOFA 2 个）
  - 保存按钮文案动态：未配置时显示「保存」，已配置时显示「替换保存」
- 方式二：无输入框，只有「从浏览器自动获取」按钮 + cookie 状态 + 「重新获取」提示
- 方式三：`<textarea>` cookie 粘贴框

#### 5.4 重构操作函数
- `testConnection()`：根据当前方式调用不同测试端点（方式一→`/test` API key，方式二/三→`/cookies/test`）
- `save()`：方式一→`saveCredentials`（合并写入，保留 cookies），方式二→`autoExtractCookies`，方式三→`saveCookies`
  - 方式一保存时，若检测到已配置，弹出确认框 `确定要用新输入的 API 密钥替换现有配置吗？`，确认后才保存
- `clear()`：方式一→`clearCredentials`（清 API key，保留 cookies），方式二/三→`clearCookies`
- 每次方式切换或保存/清除后刷新 `renderMethodStatus()`

#### 5.5 `ApiCredentialManager` 模块（L170-222）新增 5 个函数
- `getCookiesStatus(source)` → GET `/credentials/<source>/cookies`
- `saveCookies(source, cookieString)` → POST `/credentials/<source>/cookies`
- `autoExtractCookies(source)` → POST `/credentials/<source>/cookies/auto`
- `testCookies(source)` → POST `/credentials/<source>/cookies/test`
- `clearCookies(source)` → DELETE `/credentials/<source>/cookies`

#### 5.6 其他前端调整
- **`IPResourceUi.isSourceConfigured()`（约 L730）**：改为 `api_key_configured || cookies_configured`
- **`refreshCredentialBadges()`**：选项文本改为 "Shodan (已配置-API)" / "Shodan (已配置-Cookie)" / "Shodan (已配置-全部)" / "Shodan (未配置)"，区分生效方式

### 6. Fetch 失败时的引导增强
**文件**：`static/script.js` `startFetch()`（L765-798）
- 当 fetch 返回错误时，不仅显示红字，还追加「点击此处重新配置/更换」链接，打开 `ApiCredentialUi.open(source)` 并预选到失效的方式
- Spider 返回的 error 应包含是哪种方式失败（如 `"API 密钥余额不足，请更换 API key 或切换到 Cookie 模式"` / `"Cookie 登录态已过期，请重新获取"`），前端据此定位到对应方式 Tab

## Assumptions & Decisions

1. **API 优先**：同时配置了 API key 和 cookie 时，fetch 使用 API 模式。Cookie 仅在无 API key 或 API 失败时启用。
2. **3 方式可共存**：用户可同时配置方式一和方式三，系统自动选最优。清除一种不影响另一种。
3. **方式状态总览**：Modal 顶部始终显示 3 方式各自状态 + 当前生效方式，一目了然。
4. **可更改/可替换（核心）**：
   - **API key 可替换**：方式一表单中输入新 API key → 测试 → 「替换保存」→ 覆盖旧 key，cookies 不受影响。无需先清除。
   - **Cookie 可替换**：方式二重新自动获取 / 方式三粘贴新 cookie → 保存 → 覆盖旧 cookie，api_key 不受影响。
   - 每种方式可反复保存（覆盖旧值）、测试（验证有效性）、清除（移除）。不存在"一次配置锁死"。
5. **合并写入**：`save_credentials` 改为合并写入，保存 API key 时保留 cookies，反之亦然。这确保替换一种方式不会意外丢失另一种方式的配置。
6. **不返回明文**：后端 GET 接口不返回 API key / cookie 明文，前端表单始终为空，用户输入新值即表示替换。
7. **browser_cookie3 优先级**：自动获取依次尝试 Chrome → Firefox → Edge。
8. **不翻页**：只抓第 1 页搜索结果（约 10-25 IP），用户已确认可接受。
9. **FOFA Cloudflare 限制**：FOFA cookie 模式可能被 Cloudflare JS challenge 拦截。Shodan 无此问题。在 FOFA cookie guide 中如实标注此风险。
10. **不修改 Sonar/IPDeny**：这两个免费源保持不变。
11. **凭据文件 schema**：`api_credentials.json` 中 shodan/fofa 条目新增 `cookies` 字段（dict），与 api_key/email/key 并列。
12. **ToS 风险**：网页爬取可能违反服务条款，用户自行承担。

## Verification Steps

1. **依赖**：`pip install browser_cookie3 beautifulsoup4` 成功
2. **凭据存储（合并写入验证）**：
   - `save_credentials("shodan", {"api_key": "keyA"})` → `get_credentials("shodan")` 返回 `{api_key: "keyA", updated_at}`
   - `save_cookies("shodan", {"c":"d"})` → `get_credentials("shodan")` 返回 `{api_key: "keyA", cookies: {c:"d"}, updated_at}`（api_key 保留）
   - `save_credentials("shodan", {"api_key": "keyB"})` → `get_credentials("shodan")` 返回 `{api_key: "keyB", cookies: {c:"d"}, updated_at}`（cookies 保留，api_key 已替换）
   - `clear_cookies("shodan")` → api_key 仍在，cookies 已删
3. **API 路由**：
   - `GET /credentials` 返回 `{configured, api_key_configured, cookies_configured}` 三个字段
   - `POST /credentials/shodan/cookies` 保存 cookie 字符串
   - `POST /credentials/shodan/cookies/auto` 本地有登录态时返回 `{success:true, count:N}`
   - `POST /credentials/shodan/cookies/test` 返回 `{valid, ip_count}`
   - `DELETE /credentials/shodan/cookies` 清除
4. **Spider**：
   - 仅 cookie 无 api_key → `_fetch_via_web` 生效，文件生成含 IP
   - 有 api_key → API 模式（优先）
   - 都没有 → 错误提示引导配置
5. **前端 3 方式面板**：
   - Modal 显示方式状态总览（3 方式各自状态 + 生效方式）
   - 3 个 Tab 可切换，各有详细 guide（含更换场景说明）
   - 方式一：当前状态提示 + API key 表单 + 测试 + 保存/替换保存 + 清除
   - 方式二：自动获取按钮 + 状态 + 测试 + 清除
   - 方式三：textarea 粘贴 + 测试 + 保存 + 清除
   - 切换 Tab 时 guide 和 form 正确切换
   - 保存/清除后总览状态刷新
6. **可更改/替换配置（核心验证）**：
   - **API key 替换**：已配置 API key A → 打开 Modal 方式一 → 看到提示"已配置(••••A)" → 输入新 key B → 测试成功 → 点「替换保存」→ 确认框 → 总览仍显示方式一已配置 → fetch 使用 key B（非 A）
   - **方式共存**：配置 API key → 切到方式三粘贴 cookie → 保存 → 总览显示两种均配置 → 清除 API key → 总览更新为仅 Cookie → cookies 仍在
   - **Cookie 替换**：已配置 cookie → 方式三粘贴新 cookie → 保存 → 旧 cookie 被覆盖
7. **端到端**：本地登录 Shodan → 方式二自动获取 → 测试成功 → Fetch Modal 选 Shodan → 开始获取 → 文件生成
