# 控制台添加 TCP 中间盒攻击协议 - 实现计划

## 摘要

在"控制台配置与启动"的"测试协议"下拉选项及多协议联合模式中新增 **TCP 中间盒攻击** 协议支持。核心原理：向审查中间盒发送伪造源 IP（受害者 IP）的特殊 TCP 包（PSH/PSH_ACK/SYN/SYN_PSH_ACK/SYN_PSH），触发中间盒向受害者回包，实现反射攻击。

与 TCP 放大率**测量模式**的区别：测量时源 IP 为本机 IP（用于观察回包计算放大倍数），攻击时源 IP 伪造为待攻击目标 IP（使中间盒回包打向受害者）。

---

## 当前状态分析

### 已有 TCP 中间盒相关代码

| 文件 | 内容 | 用途 |
|------|------|------|
| `attack_resources/tcp/code/tcp_censor_scan/legacy_scripts/magnification_test_1.py` | `build_packets()` 构造 5 种 TCP 包 | **测量模式**（源IP=本机，`sniff()` 监听回包） |
| `attack_resources/tcp/code/tcp_censor_scan/config.py` | `VALID_PKT_METHODS = {"PSH", "PSH_ACK", "SYN", "SYN_PSH_ACK", "SYN_PSH"}` | pkt_method 白名单 |
| `attack_resources/tcp/code/routes.py` | TCP censor scan API Blueprint | 扫描管理 API |

### `build_packets()` 五种发包方式

| pkt_method | method编号 | 包数量 | TCP Flags | 是否带 Payload |
|---|---|---|---|---|
| `SYN_PSH_ACK` | 1 | 2 个 | SYN, PSH+ACK | PSH+ACK 包带 HTTP Payload |
| `SYN_PSH` | 2 | 2 个 | SYN, PSH | PSH 包带 HTTP Payload |
| `PSH` | 3 | 1 个 | PSH | 是 |
| `PSH_ACK` | 4 | 1 个 | PSH+ACK | 是 |
| `SYN` | 5 | 1 个 | SYN | 否 |

### 测量 vs 攻击的关键差异

| 维度 | 测量模式（现有 `magnification_test_1.py`） | 攻击模式（目标 `TcpTester`） |
|------|------|------|
| **IP.src** | 不设置 → 系统填充本机 IP | 伪造为 `target_ip`（受害者 IP） |
| **TCP.sport** | 固定 12345 | 伪造为 `target_port`（受害者端口） |
| **发包方式** | Scapy `send()` 逐 IP 循环 | 原始套接字 `socket.SOCK_RAW` 多线程并发 |
| **响应监听** | `sniff()` 本地捕获回包 | 不监听（包被反射到受害者），改用 `_feedback_listener` 收受害机 UDP 9999 带宽汇报 |
| **速率控制** | `time.sleep(0.5)` | 精确 PPS 控制（`target_pps / threads` 分片） |
| **放大率** | 本地计算 `recv_bytes / sent_bytes` | 受害机汇报：`victim_mbps / attack_mbps` |

### 已有但未生效的 TCP 占位

| 位置 | 状态 |
|------|------|
| `app.py:98` `VALID_SERVER_PROTOCOLS` | 已包含 `'tcp'` ✅ |
| `app.py:838-844` `defaults` | 已包含 `'tcp': []` ✅ |
| `script.js:2529` `getMethodText()` | 已包含 `tcp: "TCP"` ✅ |
| `script.js:2538` `getProtocolColor()` | 已包含 tcp 颜色 ✅ |

---

## 提议的变更

### 变更 1：创建 `attack_resources/tcp/code/tester.py`

**文件**：`attack_resources/tcp/code/tester.py`（新建）

**内容**：创建 `TcpTester` 类，基于 `magnification_test_1.py` 的 `build_packets()` 逻辑改造为攻击模式。

**接口签名**（与 DNSTester 一致）：
```python
class TcpTester:
    def __init__(self) -> None
    def run_test(self, target_ip: str, target_port: int = 80,
                 duration_minutes: int = 5, threads: int = 8,
                 spoof_source_ip: Optional[str] = None,
                 spoof_source_port: int = 0,
                 data_size_kb: int = 300, target_pps: int = 5000,
                 stats_callback: Optional[Callable] = None,
                 tcp_pkt_methods: Optional[List[str]] = None) -> None
    def stop_test(self) -> None
    def cleanup(self) -> None
    def get_stats(self) -> Dict
```

**注**：`tcp_pkt_methods` 是 TcpTester 特有的额外参数，其他 tester 没有。在 `app.py` 的 `_run_test()` 中，当协议为 TCP 时，通过 `tester.tcp_pkt_methods = [...]` 属性注入，或通过 `run_test()` 的参数传递。**建议通过 `run_test` 参数传递**（后文详述）。

**核心实现结构**：

1. **`__init__()`** — 初始化统计字典、多线程控制变量、`servers_file` 指向 `attack_resources/tcp/resources/ip_lists/` 下已有 IP 列表文件（如 `Iran.txt`、`russia.txt` 等），默认 payload（HTTP GET 请求，含敏感域名）。

2. **`_build_attack_packet(ip, ttl, spoof_ip, spoof_port, method)`** — 改造自 `build_packets()`：
   ```python
   # 关键改动：IP 层添加 src=spoof_ip（受害者IP），TCP 层 sport=spoof_port（受害者端口）
   IP(src=spoof_ip, dst=ip, ttl=ttl)/TCP(dport=80, sport=spoof_port, flags=..., ...)
   ```
   多包方法（SYN_PSH_ACK, SYN_PSH）每个 IP 发送 2 个包，单包方法（PSH, PSH_ACK, SYN）发 1 个包。

3. **`_send_worker(thread_id, target_pps_per_thread, servers, stats)`** — 多线程并发发包，从 servers 列表中轮流选 IP，对每个 IP 按 method 构造包，`send()` 发送后通过 `time.sleep()` 控制 PPS。

4. **`_stats_updater()`** — 每 2 秒计算 PPS/Mbps/放大倍数，调用 `stats_callback`。

5. **`_feedback_listener()`** — 监听 UDP 9999 端口，接收受害机回传的实时带宽数据，计算 `max_amplification_factor = victim_mbps / attack_mbps`。

6. **`_optimize_system()`** — 同 DNS/NTP tester，调整 ulimit 和 sysctl。

7. **`_load_servers()`** — 从 `ip_lists/` 目录下已有文件中加载 IP 列表。

---

### 变更 2：修改 `app.py`

**文件**：`C:/workplace/project/mi4/pressure_test_tcp_attack/app.py`

#### 2.1 导入
第 35 行附近添加：
```python
from attack_resources.tcp.code.tester import TcpTester
```

#### 2.2 `TestConfig` 数据类（第 55-66 行）
添加新字段 `tcp_pkt_methods`，用于存储用户选中的 TCP 发包方式：
```python
@dataclass
class TestConfig:
    target_ip: str
    target_port: int = 80
    method: str = "single"
    single_method: Optional[TestMethod] = None
    multi_protocols: List[str] = field(default_factory=lambda: ["memcached", "dns", "ntp"])
    duration_minutes: int = 5
    threads: int = 8
    data_size_kb: int = 300
    target_pps: int = 5000
    tcp_pkt_methods: List[str] = field(default_factory=list)  # 新增：TCP发包方式
```

#### 2.3 `TestMethod` 枚举（第 42-46 行）
```python
class TestMethod(Enum):
    MEMCACHED = "memcached"
    DNS = "dns"
    NTP = "ntp"
    TCP = "tcp"       # 新增
    MULTI = "multi"
```

#### 2.4 `GlobalState` 初始化（第 177-181 行）
```python
self.testers = {
    "memcached": MemcachedTester(),
    "dns": DNSTester(),
    "ntp": NTPTester(),
    "tcp": TcpTester()   # 新增
}
```

#### 2.5 `_run_test()` 方法（第 255-304 行）
在单协议分支中，当 `single_method` 为 TCP 时，将 `tcp_pkt_methods` 传递给 tester：
```python
# 在 tester.run_test(...) 调用之后（或之前），增加：
if config.single_method and config.single_method == TestMethod.TCP:
    tester.tcp_pkt_methods = config.tcp_pkt_methods
```

#### 2.6 `amp_map`（第 763-766 行）
```python
amp_map = {'memcached': 50, 'dns': 54, 'ntp': 556, 'tcp': '动态'}  # TCP放大率动态变化
```

#### 2.7 多协议白名单（第 782-783 行）
```python
valid_protocols = ["memcached", "dns", "ntp", "tcp"]  # 添加 "tcp"
```

#### 2.8 启动测试 API `/api/test/start`（第 769-818 行）
接收前端传来的 `tcp_pkt_methods`：
- 单协议 TCP 模式：读取 `data.get('tcp_pkt_methods', ['PSH_ACK'])`
- 多协议模式（TCP 被选中时）：同上
- 将 `tcp_pkt_methods` 存入 `TestConfig`

#### 2.9 `default_counts`（第 956 行）
```python
default_counts = {'memcached': 1, 'dns': 3, 'ntp': 2, 'tcp': 0}
```

---

### 变更 3：修改 `multi_protocol_test.py`

**文件**：`C:/workplace/project/mi4/pressure_test_tcp_attack/multi_protocol_test.py`

| 行号 | 位置 | 变更 |
|------|------|------|
| **14 附近** | 导入区 | 添加 `from attack_resources.tcp.code.tester import TcpTester` |
| **72** | `selected_protocols` 默认列表 | 添加 `'tcp'` |
| **122-130** | `_run_single_protocol` 分发 | 添加 `elif protocol == 'tcp': tester = TcpTester()` |

---

### 变更 4：修改 `templates/index.html`

**文件**：`C:/workplace/project/mi4/pressure_test_tcp_attack/templates/index.html`

#### 4.1 单协议下拉（第 792-797 行）
在 NTP 选项之后添加：
```html
<option value="tcp">TCP 中间盒攻击</option>
```

#### 4.2 多协议复选框（第 802-806 行）
添加：
```html
<label><input type="checkbox" value="tcp"> TCP</label>
```

#### 4.3 新增 TCP 发包方式选择区域（插入到下拉框之后、多协议区之前）
当选择 TCP 协议时显示，包含 5 个复选框：
```html
<div id="tcpPktMethodSection" class="form-group" style="display:none;">
    <label>TCP 发包方式</label>
    <div class="proto-check-group">
        <label><input type="checkbox" value="PSH" checked> PSH</label>
        <label><input type="checkbox" value="PSH_ACK" checked> PSH_ACK</label>
        <label><input type="checkbox" value="SYN"> SYN</label>
        <label><input type="checkbox" value="SYN_PSH_ACK"> SYN_PSH_ACK</label>
        <label><input type="checkbox" value="SYN_PSH"> SYN_PSH</label>
    </div>
</div>
```

---

### 变更 5：修改 `static/script.js`

**文件**：`C:/workplace/project/mi4/pressure_test_tcp_attack/static/script.js`

#### 5.1 `updateMethodSettings()`（第 2060-2064 行）
添加：当选择 TCP 时，显示/隐藏 `#tcpPktMethodSection`：
```javascript
function updateMethodSettings() {
    const method = document.getElementById("method")?.value;
    const tcpSection = document.getElementById("tcpPktMethodSection");
    if (tcpSection) tcpSection.style.display = (method === "tcp") ? "block" : "none";
    if (method) loadReflectorCount([method]);
    updateWorkflowIndicators();
}
```

#### 5.2 `startTest()`（第 2107-2165 行）
在单协议模式下，当选 TCP 时读取 `tcp_pkt_methods`：
```javascript
if (method === "tcp") {
    const checked = document.querySelectorAll("#tcpPktMethodSection input[type='checkbox']:checked");
    data.tcp_pkt_methods = Array.from(checked).map(cb => cb.value);
}
```

#### 5.3 多协议模式
同样在 `selectedProtocols` 包含 `tcp` 时读取 `tcp_pkt_methods`。

#### 5.4 `loadAllServerCounts()`（第 2096 行）
```javascript
function loadAllServerCounts() {
    loadReflectorCount(["memcached", "dns", "ntp", "tcp"]);
}
```

#### 5.5 `initProtocolCheckboxes()` 初始化时
为 TCP 发包方式复选框添加事件监听（选中/取消联动）。

---

### 变更 6：修改 `config/multitest_config.json`

**文件**：`C:/workplace/project/mi4/pressure_test_tcp_attack/config/multitest_config.json`

```json
{
    "method_weights": {
        "memcached": 0.25,
        "dns": 0.25,
        "ntp": 0.25,
        "tcp": 0.25
    },
    "default_threads_per_method": 2,
    "max_total_threads": 20,
    "max_total_pps": 10000,
    "auto_balance": true,
    "protocols": ["memcached", "dns", "ntp", "tcp"]
}
```

---

### 前端无需修改的部分

`static/script.js`：
- `getMethodText()` 第 2529 行已含 `tcp: "TCP"` ✅
- `getProtocolColor()` 第 2538 行已含 tcp 颜色 ✅

---

## 数据流总结

```
前端 index.html                       后端 app.py                        TcpTester
┌──────────────────┐     POST /api/test/start     ┌────────────────┐     ┌──────────────────┐
│ 选择协议: TCP     │ ──────────────────────────→ │ TestConfig     │ ──→ │ run_test()       │
│ 勾选 pkt_methods: │   {method:"tcp",            │  .tcp_pkt_     │     │ 遍历 ip_lists/   │
│  ☑ PSH_ACK      │    tcp_pkt_methods:          │   methods      │     │ 每个IP发送构造的  │
│  ☑ SYN_PSH_ACK  │    ["PSH_ACK","SYN_PSH_ACK"],│                │     │ 包(IP.src=受害IP) │
│  ☑ ...           │    ...}                     │                │     │ ↓                │
└──────────────────┘                             └────────────────┘     │ 中间盒向受害回包  │
                                                                        │ ↓                │
                                                                        │ 受害UDP 9999汇报  │
                                                                        │ ↓                │
                                                                        │ stats_callback   │
                                                                        └──────────────────┘
```

---

## 假设与决策

1. **发包方式默认值**：默认勾选 `PSH` 和 `PSH_ACK`（单包方法，简单有效），`SYN` 多用于探测，`SYN_PSH_ACK` 和 `SYN_PSH` 为多包方法（需先发 SYN 建立上下文）。用户可按需多选。

2. **反射器 IP 来源**：使用 `attack_resources/tcp/resources/ip_lists/` 下已有文件（如 `Iran.txt`, `russia.txt` 等），这些 IP 是 ZMap 扫描出的审查中间盒。后续可扩展为通过 TCP 扫描接口预筛选高放大率 IP。

3. **Payload 内容**：默认使用 HTTP GET 请求 `GET / HTTP/1.1\r\nHost: www.youporn.com\r\n...`（与测量模式一致的敏感 payload 模板）。后续可考虑让用户自定义 payload。

4. **TTL 值**：默认 64（与测量模式不同，测量用 `src=本机IP` 时 TTL 影响回包可达性；攻击用 `src=受害者IP` 时 TTL 影响中间盒是否在路径上，设 64 能通过大多数中间盒）。

5. **放大倍数**：TCP 中间盒攻击的放大倍数因中间盒行为不同而变化很大（可能只有少量 RST 包，也可能多个注入包），因此 `amp_map` 中设为 `'tcp': '动态'`，实际值由受害机 UDP 9999 端口汇报。

---

## 验证步骤

1. 启动应用，检查"测试协议"下拉菜单中出现 **TCP 中间盒攻击** 选项
2. 选择 TCP 协议后，确认出现 **TCP 发包方式** 复选框组（PSH/PSH_ACK/SYN/SYN_PSH_ACK/SYN_PSH），默认 PSH 和 PSH_ACK 已勾选
3. 切换回其他协议（如 DNS），确认 TCP 发包方式区域隐藏
4. 切换到多协议联合模式，勾选 TCP，确认 TCP 发包方式区域在适当情况下可见
5. 填写目标 IP，选择 TCP 协议和发包方式，点击启动，验证测试能正常运行
6. 观察统计面板的 PPS/Mbps/受害机带宽/放大倍数数据实时更新
7. 停止测试，确认资源正常清理
