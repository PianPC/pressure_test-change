# 统一"优质IP"文件管理 —— 实施计划

## 摘要

将所有协议（DNS、Memcached、NTP、TCP）的 IP 资源文件统一使用 `attack_resources/{proto}/resources/ip_lists/` 多文件目录管理。现有 TCP 已实现此模式，需要将 DNS/Memcached/NTP 从单文件 `servers.txt` 迁移至多文件目录，并在多协议模式下支持各协议独立选择 IP 文件。

---

## 一、现状分析

| 维度 | TCP | DNS / Memcached / NTP |
|------|-----|----------------------|
| IP 文件目录 | `attack_resources/tcp/resources/ip_lists/` (多 .txt) | `attack_resources/{proto}/resources/servers.txt` (单文件) |
| 后端 `list_server_source_paths()` | glob 整个 `ip_lists/` 目录 | 返回单个 `servers.txt` |
| 后端 `resolve_server_sources()` | 支持多文件并集 | 仅取第一个文件 |
| 前端 `getDefaultServerSources()` | 选中所有文件 | 仅选第一个 |
| 前端 资源池 Modal | 多文件 checkbox 选择 + 文件切换编辑 | 仅 1 个文件可选 |
| 测试器 `_load_servers()` | 遍历 `ip_lists/*.txt` | 读单个 `servers.txt` |
| Console 多协议模式 | 无独立 IP 文件选择 | - |

---

## 二、设计原则

1. **统一模型**：所有协议均使用 `attack_resources/{proto}/resources/ip_lists/`，每个国家/地区一个 `.txt`，方便分类管理
2. **向后兼容**：启动时自动将旧 `servers.txt` 迁移至 `ip_lists/default.txt`
3. **独立选择**：多协议模式下每个协议独立选择 IP 文件集合
4. **沿用现有交互**：复用已有"查看/编辑源文件"Modal，不做新 UI 模式

---

## 三、修改步骤

### 步骤 1：后端 `app.py` — 统一服务器源函数

**1.1 `list_server_source_paths()`（~378 行）**

移除 `if method == 'tcp'` 特殊判断，所有协议统一使用 `ip_lists/` 目录：

```python
def list_server_source_paths(method: str) -> List[Path]:
    root = Path(ATTACK_RESOURCES_ROOT) / method / 'resources' / 'ip_lists'
    if not root.exists():
        return []
    return sorted(path for path in root.glob('*.txt') if path.is_file())
```

**1.2 `get_server_file()`（~372 行）**

默认路径指向 `ip_lists/default.txt`：

```python
def get_server_file(method: str) -> str:
    return os.path.join(ATTACK_RESOURCES_ROOT, method, 'resources', 'ip_lists', 'default.txt')
```

**1.3 `resolve_server_sources()`（~422 行）**

移除 TCP 特殊分支，统一多文件逻辑：

```python
def resolve_server_sources(method: str, sources: Optional[List[str]] = None) -> List[Path]:
    source_paths = list_server_source_paths(method)
    if not source_paths:
        return []
    if not sources:
        return source_paths
    selected_names = {Path(str(source)).name for source in sources if str(source).strip()}
    resolved = [path for path in source_paths if path.name in selected_names]
    return resolved or source_paths
```

**1.4 `resolve_server_source()`（~408 行）**

移除 TCP 特殊分支：

```python
def resolve_server_source(method: str, source: Optional[str] = None) -> Optional[Path]:
    source_paths = list_server_source_paths(method)
    if source:
        source_name = Path(str(source)).name
        for path in source_paths:
            if path.name == source_name:
                return path
        return None
    if source_paths:
        return source_paths[0]
    return None
```

**1.5 `get_server_file_content()` 路由（~872 行）**

移除 `if method == 'tcp' and source_path is None` 判断，统一为 `if source_path is None` 返回 404。

**1.6 `get_server_count()` 路由（~958 行）**

移除"仅处理 memcached/dns/ntp 排除 TCP"的特殊逻辑，改为统一遍历所有协议：

```python
for protocol in protocols:
    if protocol in VALID_SERVER_PROTOCOLS:
        source_paths = list_server_source_paths(protocol)
        count = sum(count_server_entries_in_file(p) for p in source_paths)
        protocol_counts[protocol] = count
        total_count += count
```

**1.7 新增 `migrate_server_files()` 函数**

在 `create_required_directories()` 之后调用，将旧 `servers.txt` 迁移到 `ip_lists/default.txt`：

```python
def migrate_server_files():
    for protocol in VALID_SERVER_PROTOCOLS:
        ip_lists_dir = Path(ATTACK_RESOURCES_ROOT) / protocol / 'resources' / 'ip_lists'
        ip_lists_dir.mkdir(parents=True, exist_ok=True)
        old_file = Path(ATTACK_RESOURCES_ROOT) / protocol / 'resources' / 'servers.txt'
        new_file = ip_lists_dir / 'default.txt'
        if old_file.exists() and not new_file.exists():
            new_file.write_text(old_file.read_text(encoding='utf-8'), encoding='utf-8')
        elif not old_file.exists() and not new_file.exists():
            new_file.write_text('# 每行一个反射器IP或域名\n', encoding='utf-8')
```

**1.8 `create_required_directories()`**

增加各协议的 `ip_lists` 子目录。

**1.9 `TestConfig` dataclass**

新增 `protocol_sources` 字段：

```python
protocol_sources: Dict[str, List[str]] = field(default_factory=dict)
```

**1.10 `start_test` 路由和 `_run_test` 方法**

接收前端传来的 `protocol_sources`，多协议模式传递给 `MultiProtocolTester`，单协议模式传递 `source_files`。

---

### 步骤 2：三个测试器 `tester.py` — 统一加载逻辑

**模式**：参照 TCP 已有的 `_load_servers()`（`tcp/code/tester.py` 236-256 行），从 `ip_lists/` 目录遍历所有 `.txt`。

修改文件：
- `attack_resources/dns/code/tester.py`
- `attack_resources/ntp/code/tester.py`
- `attack_resources/memcached/code/tester.py`

每个文件修改：
1. `__init__` 中 `self.servers_file` → `self.servers_dir = Path('attack_resources/{proto}/resources/ip_lists')`
2. `_load_servers()` 改为遍历 `servers_dir/*.txt`，增加可选 `source_files` 参数以支持按指定文件列表加载
3. `run_test()` 签名增加 `source_files: Optional[List[str]] = None` 参数，传递给 `_load_servers()`

---

### 步骤 3：`multi_protocol_test.py` — 按协议传递源文件

- `run_test()` 增加 `protocol_sources: Optional[Dict[str, List[str]]] = None` 参数
- `_run_single_protocol()` 将对应协议的 `source_files` 传递给 tester

---

### 步骤 4：前端 — 多协议模式下独立 IP 文件选择

**4.1 `script.js` — `getDefaultServerSources()`（~561 行）**

移除 TCP 特殊判断，所有协议默认全选：

```javascript
function getDefaultServerSources(proto, sources) {
    if (!sources.length) return [];
    return sources.map((item) => item.name);
}
```

**4.2 `script.js` — 新增多协议源文件管理**

```javascript
let multiProtoSelectedSources = {};  // {proto: [filename, ...]}
```

在 `startTest()` 中多协议模式下收集每个协议的源文件选择，填入 `data.protocol_sources`。

**4.3 `templates/index.html` — 多协议区域增加资源选择按钮**

在 `#multiProtocolSection` 中，每个协议复选框旁增加"选择资源"按钮：

```html
<div class="multi-proto-row">
    <label><input type="checkbox" value="memcached" checked> Memcached</label>
    <button type="button" class="btn proto-source-btn" data-proto="memcached">
        选择IP文件: <span class="proto-source-label">全部文件</span>
    </button>
</div>
```

点击按钮时临时切换 `currentProto`，复用已有的 `serverSourceModal` 进行多文件选择。选择后更新按钮标签显示当前选中的文件数或文件名。

**4.4 `static/style.css`**

新增 `.multi-proto-row` 和 `.proto-source-btn` 样式，使协议选择行整洁排列。

---

## 四、修改文件清单与依赖顺序

| 顺序 | 文件 | 变更要点 |
|------|------|---------|
| 1 | `app.py` | 统一 `list_server_source_paths()` 等 6 个函数；新增 `migrate_server_files()`；`TestConfig` 增加字段 |
| 2 | `attack_resources/dns/code/tester.py` | 多文件加载 + `source_files` 参数 |
| 3 | `attack_resources/ntp/code/tester.py` | 同上 |
| 4 | `attack_resources/memcached/code/tester.py` | 同上 |
| 5 | `multi_protocol_test.py` | 增加 `protocol_sources` 参数 |
| 6 | `templates/index.html` | 多协议区域增加 per-protocol 资源选择按钮 |
| 7 | `static/script.js` | 统一默认选择逻辑；多协议源文件管理；事件绑定 |
| 8 | `static/style.css` | 新增样式 |

---

## 五、风险与缓解

1. **旧 servers.txt 丢失**：`migrate_server_files()` 仅在 `default.txt` 不存在时迁移，不作删除。旧文件保留在磁盘上。
2. **TCP 已有 ip_lists/**：迁移逻辑检测到已有文件则跳过，不影响现有数据。
3. **测试用例断言单文件行为**：`tests/test_server_sources_api.py` 等需更新断言路径。
4. **多协议 Modal 打开时 currentProto 切换**：在打开/关闭时保存和恢复，避免干扰资源池视图状态。

---

## 六、验证步骤

1. 启动应用，确认迁移日志输出，DNS/Memcached/NTP 的 `servers.txt` 内容已复制到 `ip_lists/default.txt`
2. 在资源池视图切换各协议，确认多文件选择 Modal 正常显示和编辑
3. 在各协议 `ip_lists/` 下新增 `.txt` 文件并添加 IP，确认资源池地图和统计刷新
4. 单协议模式下启动测试，确认使用选中的 IP 文件
5. 多协议模式下为每个协议选择不同的 IP 文件，确认各协议独立使用各自文件
