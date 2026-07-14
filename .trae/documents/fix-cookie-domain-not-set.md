# 修复 Cookie Domain 未设置导致请求不带 Cookie 的根因

## 摘要

FOFA（及 Shodan）Cookie 模式一直失败的根因是：`session.cookies.update(cookies_dict)` 不会设置 cookie 的 `domain` 字段，导致 `requests` 发送请求到 `fofa.info` / `shodan.io` 时**不会带上任何 cookie**。所有请求实际以"未登录"状态发出，FOFA 返回的页面无登录态、Vue 数据中无 `assets`，因此解析到 0 个 IP。

用户的 Cookie 字符串格式完全正确（`fofa_theme=dark; ...; fofa_token=eyJ...`，含 `fofa_token` JWT），问题完全在后端 cookie 设置方式。

参考实现 `ip_collector/collectors/fofa_scraper.py` 第 121 行用 `session.cookies.set(name, value, domain='fofa.info')` 逐个设置 domain，所以能成功。

## 当前状态分析

### 数据流（当前，有 bug）
1. 前端粘贴 cookie 字符串 → `save_cookies_route`（[attack_resource_api.py:1779](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/attack_resource_api.py#L1779)）调 `_parse_cookie_string` → 返回 dict `{"fofa_token": "eyJ...", ...}`
2. 存入 `api_credentials.json`：`{"fofa": {"cookies": {"fofa_token": "eyJ...", ...}}}`
3. `get_cookies("fofa")`（[credential_store.py:97](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/credential_store.py#L97)）→ 返回 dict
4. **BUG**：`fofa_spider.py` [第 228 行](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py#L228) 和 [第 449 行](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py#L449) `session.cookies.update(cookies)` — **domain 为空，请求不带 cookie**
5. 同样 bug 在 `shodan_spider.py` [第 157 行](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py#L157) 和 [第 311 行](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py#L311)

### 参考实现（正确）
`ip_collector/collectors/fofa_scraper.py` [第 114-121 行](file:///C:/Users/PPCa1/AppData/Roaming/TRAE%20SOLO%20CN/ModularData/ai-agent/work-mode-projects/6a55def0d9d0da2709776444/ip_collector/collectors/fofa_scraper.py#L114)：
```python
def _parse_cookie_string(self, cookie_str):
    for item in cookie_str.split(';'):
        item = item.strip()
        if '=' in item:
            name, value = item.split('=', 1)
            name = name.strip()
            value = value.strip()
            if name:
                self.session.cookies.set(name, value, domain='fofa.info')  # ← 关键：设置 domain
```

### 参考实现的完整 headers（比我们当前更全，有助绕过反爬）
`fofa_scraper.py` [第 57-68 行](file:///C:/Users/PPCa1/AppData/Roaming/TRAE%20SOLO%20CN/ModularData/ai-agent/work-mode-projects/6a55def0d9d0da2709776444/ip_collector/collectors/fofa_scraper.py#L57)：
```python
self.session.headers.update({
    'User-Agent': random.choice(USER_AGENTS),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
})
```

## 提议的修改

### 修改 1：fofa_spider.py — cookie domain 设置 + headers 补全
**文件**：[attack_resources/shared/spiders/fofa_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py)

**1a. 新增模块级常量 `_COOKIE_DOMAIN`**（在 `USER_AGENTS` 之后）：
```python
_COOKIE_DOMAIN = "fofa.info"
```

**1b. 新增辅助方法 `_set_cookies_to_session`**（在 `__init__` 之后）：
```python
def _set_cookies_to_session(self, session, cookies):
    """将 cookies dict 逐个 set 到 session，带 domain（参考 ip_collector 实现）。
    
    session.cookies.update(dict) 不设置 domain，导致 requests 发送请求时不带 cookie。
    必须用 session.cookies.set(name, value, domain=...) 逐个设置。
    """
    for name, value in cookies.items():
        session.cookies.set(name, str(value), domain=_COOKIE_DOMAIN)
```

**1c. 替换 `_fetch_via_web` 第 228 行**：
- `session.cookies.update(cookies)` → `self._set_cookies_to_session(session, cookies)`

**1d. 替换 `check_web_cookies` 第 449 行**：
- `session.cookies.update(cookies)` → `self._set_cookies_to_session(session, cookies)`

**1e. 补全 headers**（`_fetch_via_web` 第 262-268 行和 `check_web_cookies` 第 450-456 行）：
在现有 headers 基础上新增（对齐参考实现，有助绕过反爬）：
```python
headers = {
    "User-Agent": random.choice(USER_AGENTS),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
```

### 修改 2：shodan_spider.py — 同样修复 cookie domain
**文件**：[attack_resources/shared/spiders/shodan_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py)

**2a. 新增模块级常量 `_COOKIE_DOMAIN`**：
```python
_COOKIE_DOMAIN = ".shodan.io"
```
（Shodan cookie domain 是 `.shodan.io`，覆盖 `www.shodan.io` 和 `shodan.io`）

**2b. 新增辅助方法 `_set_cookies_to_session`**（同 fofa，但 domain 用 shodan 的）

**2c. 替换 `_fetch_via_web` 第 157 行和 `check_web_cookies` 第 311 行**：
- `session.cookies.update(cookies)` → `self._set_cookies_to_session(session, cookies)`

**2d. 补全 headers**（对齐参考实现的 Sec-Fetch-* 头，Shodan 也适用）

### 不修改的部分
- **前端**：用户的 cookie 字符串格式正确，guide 文案已在上个 spec 修正，无需再改
- **credential_store.py**：`get_cookies` 返回 dict 的设计正确，问题在 spider 使用方式
- **attack_resource_api.py**：`_parse_cookie_string` 解析逻辑正确
- **Vue SSR 解析逻辑**：正确，只是因为 cookie 没带出去导致页面无登录态、Vue 数据无 assets

## 假设与决策

1. **根因判断依据**：`requests.cookies.RequestsCookieJar.update(dict)` 内部用 `set_cookie`，创建的 `http.cookiejar.Cookie` 对象 domain 为空字符串 `''`。`http.cookiebrain.make_cookies` 在匹配时会跳过 domain 为空的 cookie（不匹配任何 host）。参考实现明确 `domain='fofa.info'` 所以成功。

2. **domain 值选择**：
   - FOFA：`fofa.info`（参考实现用的值，匹配 `www.fofa.info` 和 `fofa.info` 需要前导点 `.fofa.info`，但参考实现用 `fofa.info` 且成功，requests 的 cookie 匹配较宽松，`fofa.info` 会匹配子域）
   - 实际上参考实现用 `fofa.info`（无前导点）且成功，我们沿用同样值即可。
   - Shodan：`.shodan.io`（带前导点，标准做法，覆盖 `www.shodan.io`）

3. **用户 cookie 格式确认**：用户提供的 cookie 字符串是标准 `name=value; name2=value2` 格式，`_parse_cookie_string` 能正确解析（`split(';')` → `split('=', 1)`）。`fofa_token` 字段存在且为 JWT 格式。格式完全正确，无需用户修改。

4. **不重构整体架构**：仅修复 cookie 设置这一根因，不扩大范围。Vue SSR 解析、多变体策略等上一轮已正确实现，cookie 修复后即可正常工作。

## 验证步骤

1. **Grep 验证**：`session.cookies.update` 在 fofa_spider.py 和 shodan_spider.py 中应**无残留**（全部替换为 `_set_cookies_to_session`）
2. **Grep 验证**：`_set_cookies_to_session` 在两个 spider 中各定义 1 次、调用 2 次
3. **Grep 验证**：`Sec-Fetch-Dest` 在两个 spider 中出现（headers 补全）
4. **语法验证**：`python -m py_compile` 两个 spider 文件通过
5. **功能验证（用户侧）**：
   - 重启服务
   - FOFA Cookie 模式「测试连接」应返回 `{"valid": true, "login_confirmed": true, ...}`（而非"登录态已过期"）
   - FOFA「获取资源」应返回非 0 个 IP（Vue 数据含 assets）
   - Shodan Cookie 模式同理

## 受影响文件
- [attack_resources/shared/spiders/fofa_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py) — cookie domain 设置 + headers 补全
- [attack_resources/shared/spiders/shodan_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py) — 同上
