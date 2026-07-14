# 修复登录态误判导致有效响应被跳过

## 摘要

FOFA Cookie 模式仍失败的真实根因：`_fetch_via_web` 在每个搜索页请求后用 `"login" in lower_text` 做登录态检测，但 FOFA 搜索页 HTML（无论登录与否）都含有 "login" 字样（登录按钮、CSS class、JS 路径、`/login` 链接等），导致**已登录的有效响应（html_length=181682，含 Vue 数据）被误判为"登录态失效"**，直接 break 跳过所有变体，连 Vue 数据都不解析。

用户日志铁证：`html_length=181682`（这是完整的登录态页面大小）+ `含 login 标志`（被误判）+ `Cookie 登录态已过期`（错误结论）。实际 cookie 有效，Vue 数据就在那个 181KB 的 HTML 里。

**参考实现 `ip_collector` 的处理方式**：`_get_page`（[fofa_scraper.py:222-238](file:///C:/Users/PPCa1/AppData/Roaming/TRAE%20SOLO%20CN/ModularData/ai-agent/work-mode-projects/6a55def0d9d0da2709776444/ip_collector/collectors/fofa_scraper.py#L222)）**根本不在搜索页做登录态检测**。它只在 `login()` 流程里用首页关键词（`退出`/`logout`/`个人中心`等中文词）检测一次，之后爬搜索页时只检查 `status_code != 200`，拿到 HTML 就直接解析 Vue 数据。这才是正确做法。

## 当前状态分析

### 数据流（当前，有 bug）
1. cookie 正确设置 domain → 请求带上 cookie（上一轮已修复）✓
2. FOFA 返回 200 + 完整登录态页面（html_length=181682，含 Vue 数据 + assets）✓
3. **BUG**：`_fetch_via_web` 第 310 行 `"login" in lower_text` → True（页面含 login 字样）→ 误判"登录态失效" → break，跳过所有变体
4. Vue 数据**根本没被解析**，返回 0 IP

### 参考实现（正确）
- `login()` 流程：访问首页，检测中文关键词 `['退出', 'logout', '个人中心', '我的资产', '会员中心']`
- `_get_page()` 爬搜索页：**只检查 `status_code != 200`**，不做登录态检测，拿到 HTML 直接解析
- 信任 `login()` 的结果，后续搜索页不再重复检测

### 关键差异
| 项 | 参考实现 | 当前实现（bug） |
|---|---|---|
| 登录检测时机 | 仅 `login()` 一次 | 每个搜索页都检测 |
| 登录检测词 | 中文（退出/个人中心等） | 英文（login/sign in） |
| 搜索页含 login 字样 | 不检测，继续解析 | 误判失效，break |
| 302 重定向检测 | 不检测（status_code!=200 即可） | 检测 302/301 |

### 为什么英文 "login" 会误判
FOFA 页面 HTML 普遍含 "login"：
- 顶部导航栏的登录按钮（即使已登录，DOM 里仍有 login 相关 class/元素）
- CSS class 名（`.login-btn`、`.login-modal`）
- JS 路径（`/static/js/login.js`）
- Vue 组件名（`<LoginModal>`）

所以 `"login" in lower_text` 对**任何** FOFA 页面都返回 True，完全无区分能力。中文关键词（`退出`/`个人中心`）才有区分力：未登录页面没有这些词。

## 提议的修改

### 修改 1：fofa_spider.py — 移除搜索页的登录态误判
**文件**：[attack_resources/shared/spiders/fofa_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py)

**1a. `_fetch_via_web` 第 299-317 行：移除登录态检测分支**

将：
```python
# Cloudflare 检测
if response.status_code in (403, 503) or "cf-challenge" in lower_text or "cloudflare" in lower_text:
    if i == 0:
        results.append({...error: "FOFA 被 Cloudflare 拦截..."})
        break
    continue

# 登录态检测
if "login" in lower_text or "sign in" in lower_text or response.status_code in (302, 301):
    if i == 0:
        results.append({...error: "Cookie 登录态已过期..."})
        break
    continue
```

改为（对齐参考实现，只检测 Cloudflare 和非 200 状态码）：
```python
# Cloudflare 检测
if response.status_code in (403, 503) or "cf-challenge" in lower_text or "cloudflare" in lower_text:
    if i == 0:
        results.append({
            "protocol": protocol,
            "error": "FOFA 被 Cloudflare 拦截，Cookie 模式不可用，建议使用 API 密钥",
        })
        break  # 第一个就被拦截，后续也不会成功
    continue  # 后续变体被拦截，跳过

# 非 200 状态码视为失败（对齐参考实现，不做 login 关键词误判）
if response.status_code != 200:
    if i == 0:
        results.append({
            "protocol": protocol,
            "error": f"FOFA 返回非 200 状态码（{response.status_code}），Cookie 可能已失效，请重新获取",
        })
        break
    continue

# 登录态检测交给 Vue 数据解析：未登录页面无 Vue assets 数据，
# 会自然走到 0 IP 分支并返回调试信息。不在搜索页做 login 关键词误判
# （FOFA 页面普遍含 "login" 字样，如 CSS class / JS 路径，无区分力）。
```

**1b. `_fetch_via_web` 第 383-386 行：0 IP 时的 flags 检测移除 login**

将：
```python
flags = []
if "login" in last_lower_text or "sign in" in last_lower_text:
    flags.append("login")
if "cf-challenge" in last_lower_text or "cloudflare" in last_lower_text:
    flags.append("cloudflare")
```

改为（移除无区分力的 login 检测，保留 cloudflare）：
```python
flags = []
if "cf-challenge" in last_lower_text or "cloudflare" in last_lower_text:
    flags.append("cloudflare")
# 注：不再检测 "login" 关键词，因为 FOFA 页面普遍含 login 字样无区分力。
# 登录态是否真失效，由 check_web_cookies 的首页中文关键词检测判定。
```

**1c. `check_web_cookies` 第 492-496 行：修正误判逻辑**

当前 `check_web_cookies` 已经用了正确的中文关键词检测（第 489 行），但第 494 行仍保留 `"login" in lower_text` 作为辅助判断。需要移除这个无区分力的检测：

将：
```python
if not login_confirmed:
    # 也检测是否被重定向到登录页
    if "login" in lower_text or "sign in" in lower_text or response.status_code in (302, 301):
        return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}
    return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}
```

改为：
```python
if not login_confirmed:
    # 未检测到中文登录关键词即为未登录（"login" 英文词无区分力，FOFA 页面普遍含）
    return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}
```

### 修改 2：shodan_spider.py — 同样移除登录态关键词误判
**文件**：[attack_resources/shared/spiders/shodan_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py)

Shodan 同样存在 `"login" in lower_text` 误判（第 184、263、346 行）。Shodan 搜索页 HTML 也普遍含 "login" 字样（登录链接、CSS）。

**2a. `_fetch_via_web` 第 184 行：移除 login 关键词检测**

将：
```python
if response.status_code in (302, 301) or "login" in lower_text or "sign in" in lower_text:
```

改为（只检测重定向，不检测关键词）：
```python
if response.status_code in (302, 301):
```

**2b. `_fetch_via_web` 第 263 行：0 IP 时 flags 移除 login**

将：
```python
if "login" in lower_text or "sign in" in lower_text:
    flags.append("login")
```

移除该段（login 无区分力）。

**2c. `check_web_cookies` 第 346 行：同样移除 login 关键词**

将：
```python
if response.status_code in (302, 301) or "login" in lower_text or "sign in" in lower_text:
    return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}
```

改为（只检测重定向；Shodan 未登录会重定向到 `/account/login`，302 已足够）：
```python
if response.status_code in (302, 301):
    return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}
```

### 不修改的部分
- **cookie domain 设置**：上一轮已修复，正确
- **Vue SSR 解析逻辑**：正确，修复误判后即可正常解析
- **多查询变体策略**：正确
- **check_web_cookies 的首页中文关键词检测**：正确（对齐参考实现）
- **Cloudflare 检测**：保留（403/503/cf-challenge 有区分力）

## 假设与决策

1. **根因判断依据**：用户日志 `html_length=181682` 是完整登录态页面（未登录页面通常 < 50KB），`含 login 标志` 说明 "login" 字样命中，`Cookie 登录态已过期` 是误判结论。181KB 的 HTML 里大概率含 Vue assets 数据。

2. **为什么参考实现不做搜索页登录检测**：参考实现信任 `login()` 流程的首页检测结果，搜索页只关心 `status_code == 200`。这是合理的——cookie 要么有效（所有请求都有效），要么无效（所有请求都无效），没必要每个搜索页都重复检测。未登录的搜索页会返回登录页或重定向，`status_code != 200` 或 Vue 数据无 assets 自然能识别。

3. **Shodan 的 302 检测保留**：Shodan 未登录访问搜索页会 302 重定向到 `/account/login`，这个检测有区分力，保留。仅移除 `"login" in lower_text` 关键词检测（无区分力）。

4. **不重构整体架构**：仅移除误判检测，不扩大范围。

## 验证步骤

1. **Grep 验证**：`"login" in lower_text` 在 fofa_spider.py 中应**无残留**（`_fetch_via_web` 和 `check_web_cookies` 都移除）
2. **Grep 验证**：`"login" in lower_text` 在 shodan_spider.py 中应**无残留**
3. **Grep 验证**：`退出` 和 `个人中心` 在 fofa_spider.py 中保留（check_web_cookies 首页检测）
4. **Grep 验证**：`status_code != 200` 在 fofa_spider.py 中出现（新的状态码检测）
5. **语法验证**：`python -m py_compile` 两个文件通过
6. **功能验证（用户侧）**：
   - 重启服务
   - FOFA「获取资源」— 应返回非 0 个 IP（Vue 数据被正常解析）
   - FOFA「测试连接」— 仍用中文关键词检测，登录态有效时返回 `login_confirmed: true`

## 受影响文件
- [attack_resources/shared/spiders/fofa_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/fofa_spider.py) — 移除 _fetch_via_web 和 check_web_cookies 的 login 关键词误判
- [attack_resources/shared/spiders/shodan_spider.py](file:///c:/Users/PPCa1/.trae-cn/worktrees/feat-resource-manage-update-sgJ9ev/feat-create-new-branch-mnQ0uC/attack_resources/shared/spiders/shodan_spider.py) — 同上
