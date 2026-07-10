# IP资源管理界面修复计划 (V2)

## 当前状态分析

### 问题1：TCP资源获取的"IP资源"下拉不显示新爬取的资源

**根因**：TCP资源加载存在两套代码路径：
- `AttackResourceTaskController.loadResources()` ([script.js:4451](file:///c:/workplace/project/mi4/pressure_test-change/static/script.js#L4451)) → 调用 `/api/attack-resource/tcp/resources` → `list_ip_resources()` → 使用 `IPResourceManager`
- `loadTcpResources()` ([script.js:1644](file:///c:/workplace/project/mi4/pressure_test-change/static/script.js#L1644)) → 调用 `/api/attack-resource/resources`（此函数已被第二处 `initTcpScan` 定义覆盖，是死代码）

实际生效的是第一套路径。`list_ip_resources()` ([resources.py:11](file:///c:/workplace/project/mi4/pressure_test-change/attack_resources/tcp/code/tcp_censor_scan/resources.py#L11)) 从 IPResourceManager 获取资源时，返回的 `path` 是**相对路径**（如 `manual/xxx.txt`），而 TCP 后端期望**绝对路径**。

**Memcached/NTP 的正确做法**：`_list_ip_files()` 使用 `rglob` 递归搜索，返回 `path = str(p)`（绝对路径）和 `sub_dir` 字段。

### 问题2：无法编辑自动获取的txt

**根因**：`readResource()` ([script.js:99](file:///c:/workplace/project/mi4/pressure_test-change/static/script.js#L99)) 使用 `encodeURIComponent(path)` 对整个路径编码，将 `/` 编码为 `%2F`。Flask 收到 `auto%2Fipdeny%2Fcn_20240115.txt` 后，`_resolve_path()` ([ip_resource_manager.py:425](file:///c:/workplace/project/mi4/pressure_test-change/attack_resources/shared/ip_resource_manager.py#L425)) 的 `startswith("auto/")` 判断失败，路径解析到不存在位置，返回 404。

### 问题3：国家多选框只显示一行

**根因**：`.form-group select` ([style.css:253](file:///c:/workplace/project/mi4/pressure_test-change/static/style.css#L253)) 设置了 `height:32px`，CSS 优先级（0,1,1）> `.country-select`（0,1,0），全局 select 高度覆盖了 `.country-select` 的 `height:200px`。

## 修复方案

### 修复1：TCP资源加载对齐 Memcached/NTP 模式

**文件**: `attack_resources/tcp/code/tcp_censor_scan/resources.py`

修改 `list_ip_resources()` 函数，从 IPResourceManager 获取资源时：
- 使用 `full_path`（绝对路径）而非 `path`（相对路径）作为 `path` 字段
- 添加 `entry_count` 字段（与非TCP协议一致）
- 添加 `sub_dir` 字段，标识文件所在子目录（如 `manual`、`auto/ipdeny`）

```python
# 修改后
return [
    {
        "name": r["filename"].replace(".txt", ""),
        "filename": r["filename"],
        "path": r.get("full_path", r["path"]),      # 绝对路径
        "bytes": r.get("size_bytes", 0),
        "non_empty_lines": r.get("non_empty_lines", 0),
        "entry_count": r.get("non_empty_lines", 0),  # 与Memcached/NTP一致
        "sub_dir": _extract_sub_dir(r),               # 子目录信息
    }
    for r in result["resources"]
]
```

**文件**: `static/script.js` — `renderUnifiedTcpResources()` 函数

对齐 Memcached/NTP 的渲染方式：
```javascript
function renderUnifiedTcpResources(resources = []) {
    const select = document.getElementById("tcpIpFile");
    if (!select) return;
    if (!resources.length) {
        select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
        return;
    }
    select.innerHTML = resources.map((file) => {
        const location = (file.path || "").includes("shared/ip_lists") || (file.path || "").includes("shared\\ip_lists") ? "共享目录" : "TCP 目录";
        const subDir = file.sub_dir ? ` · ${file.sub_dir}` : "";
        return `<option value="${escapeHtml(file.path || "")}">${escapeHtml(file.name || file.filename)} · ${file.entry_count || file.non_empty_lines || 0} 条 · ${location}${subDir}</option>`;
    }).join("");
}
```

**文件**: `static/script.js` — 删除死代码

删除被覆盖的 `loadTcpResources()` 函数（第 1644-1683 行）和被覆盖的 `initTcpScan()` 函数（第 1622-1626 行），避免混淆。

### 修复2：编辑功能路径编码

**文件**: `static/script.js` — `readResource()`, `writeResource()`, `deleteResource()` 三个函数

将 `encodeURIComponent(path)` 改为按路径段编码，保留 `/` 分隔符：

```javascript
// 修改前
fetch(getApiUrl(`/resources/${encodeURIComponent(path)}`))
// 修改后
fetch(getApiUrl(`/resources/${path.split('/').map(encodeURIComponent).join('/')}`))
```

### 修复2b：DNS前端渲染对齐 Memcached/NTP

**文件**: `static/script.js` — `renderUnifiedDnsResources()` 函数

当前问题：
- 第4971行只检查反斜杠 `attack_resources\\shared\\ip_lists`，没检查正斜杠（Linux环境路径用正斜杠）
- 没有显示 `sub_dir` 信息

修改为与 Memcached/NTP 一致：
```javascript
function renderUnifiedDnsResources(resources = []) {
    const select = document.getElementById("dnsIpFile");
    if (!select) return;
    if (!resources.length) {
        select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
        updateDnsIpFileSummary([]);
        return;
    }
    select.innerHTML = resources.map((file) => {
        const location = (file.path || "").includes("shared/ip_lists") || (file.path || "").includes("shared\\ip_lists") ? "共享目录" : "DNS 目录";
        const subDir = file.sub_dir ? ` · ${file.sub_dir}` : "";
        return `<option value="${escapeHtml(file.path || "")}">${escapeHtml(file.name)} · ${file.entry_count || 0} 条 · ${location}${subDir}</option>`;
    }).join("");
    updateDnsIpFileSummary(resources);
}
```

### 修复3：国家多选框CSS优先级

**文件**: `static/style.css`

将 `.country-select` 选择器提升为 `.form-group select.country-select`，优先级（0,2,1）> `.form-group select`（0,1,1）：

```css
.form-group select.country-select{
  width:100%;
  height:200px;
  padding:6px;
  ...
}
```

## Web Interface Guidelines 审查

### static/script.js
- script.js:99 - `encodeURIComponent` 对路径编码导致斜杠丢失
- script.js:375 - placeholder "..." → "…"（使用省略号字符）
- script.js:1644 - 死代码 `loadTcpResources` 应删除

### static/style.css
- style.css:253 - `outline:none` 缺少 `:focus-visible` 替代
- style.css:893 - `.country-select` height 被 `.form-group select` 覆盖

### templates/index.html
- index.html:1361 - `id="ipResourceFetchStatus"` 缺少 `aria-live="polite"`

## 修改文件清单

| 文件 | 修改内容 |
|------|----------|
| `attack_resources/tcp/code/tcp_censor_scan/resources.py` | `list_ip_resources()` 返回绝对路径+sub_dir |
| `static/script.js` | 修复路径编码、对齐TCP+DNS渲染、删除死代码 |
| `static/style.css` | 提升 country-select CSS 优先级 |

## 验证步骤

1. 在IP资源管理中点击编辑自动获取的txt文件，确认能正常打开并显示内容
2. 在自动获取资源中选择IPdeny，确认国家多选框显示12行
3. 自动获取新资源后，在TCP资源获取的IP资源下拉列表中看到新资源，选择后能正常使用
4. 对比TCP/Memcached/NTP/DNS的IP资源下拉列表展示格式，确认一致性
