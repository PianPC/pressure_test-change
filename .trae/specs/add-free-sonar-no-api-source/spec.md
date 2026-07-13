# 新增 Rapid7 Sonar 免费（无 API 密钥）数据源 Spec

## Why

上一个 spec（`add-spider-api-key-onboarding`）为 Shodan/FOFA 增加了 API 密钥配置流程，但部分用户无法获取 API 密钥（注册需付费/邮箱验证/区域限制）。

关于"纯爬虫爬取 Shodan/FOFA"：**不可行**。两者都强制登录才能查看搜索结果——未登录时仅显示 1-2 条 IP 即撞登录墙，且具备强反爬机制（验证码、IP 封禁）。强行爬取只会得到极少数据并易被封禁。

## ⚠️ 实现期间发现的关键问题（Rapid7 OpenData 已商业化）

原计划采用 Rapid7 OpenData (Project Sonar) 作为免费无密钥源，但实现期间通过核实 `https://opendata.rapid7.com/about/` 发现：**该数据集现已改为商业授权访问**。about 页明确写明：

> "Access is granted on a commercial basis to qualified organizations... Access is provided through a commercial data licensing agreement... Pricing and terms are determined based on the specific use case."

具体表现：文件列表（`sonar.udp/`）仍公开可见，但点击下载会 301 重定向到 `sonardata.rapid7.com` → 302 回到列表页（返回 HTML 而非 gzip 文件）。即"列表可见、下载需商业授权"。

因此本 spec 的核心前提（"无需账户/无需密钥/无需许可"）在当前 Rapid7 站点**已不成立**。已实现的 `SonarSpider` 代码架构正确（HTML 抓取 → substring 匹配 → 下载 → 解压 → 解析 IP），对下载失败有优雅降级（返回清晰错误 "下载失败: 服务端返回了非 gzip 数据 (文件可能需要登录)"），但**当前无法实际获取 IP**。

## 当前已交付价值

尽管 Rapid7 数据下载被 gated，本 spec 仍交付了以下可用价值：
1. **前端 sonar 选项 + 引导提示升级**：Fetch Modal 新增 "Rapid7 Sonar (免费/无需API密钥)" 选项与三按钮引导提示，框架就位
2. **SonarSpider 架构**：完整实现 HTML 列表抓取 + substring 模式匹配 + 多协议独立处理 + 优雅降级，可在 Rapid7 开放访问或切换到其他类似公开数据源时复用
3. **Pattern 已修正**：NTP 实际为 `udp_ntpmonlist_123`、SSDP 实际为 `udp_upnp_1900`（原 spec 假设有误，已通过实际页面核实并修正）
4. **凭据路由兼容**：sonar 不参与凭据状态，`GET /credentials` 不含 sonar，`POST /credentials/sonar` 返回 400

## 后续可选方向（待用户决策）

由于 Rapid7 已商业化，真正"无 API 密钥"的替代方案有限，可选方向：
- **A. 内置静态启动列表**：随应用打包一份小的 DNS/NTP/SNMP/Memcached/SSDP 已知 IP 列表（离线可用，但易过期）
- **B. 自定义 URL 抓取源**：新增 spider 接受用户提供的 URL（.txt/.csv/.csv.gz），下载并解析——用户可指向自有扫描结果、付费 feed 或共享列表
- **C. 保留 Sonar 选项但更新文案**：将选项标注为 "Rapid7 Sonar (需商业授权)"，诚实告知用户
- **D. 接入其他免费源**：如 Censys 免费账户、GreyNoise Community API（均需注册但免费）



## What Changes

### 1. 新增 Sonar 爬虫
- 新建 `attack_resources/shared/spiders/sonar_spider.py`，实现 `SonarSpider` 类
- 无需任何凭据；通过 `requests` 抓取 `https://opendata.rapid7.com/sonar.udp/` HTML 列表（第 1 页即可获取最新文件）
- 按协议名匹配最新 `udp_<service>_<port>*.csv.gz` 文件
- 下载 → gzip 解压 → 解析 CSV → 提取唯一 IP → 按 limit 截断 → 写入 `ip_lists/auto/sonar/<protocol>_<date>.txt`
- 返回结构与 Shodan/FOFA spider 一致：`{"success", "source": "sonar", "files": [...], "total_queries", "successful"}`

### 2. 注册 Sonar 爬虫
- 在 `attack_resources/shared/spiders/__init__.py` 的 `SPIDERS` 字典中注册 `"sonar": SonarSpider`
- 在 `attack_resources/shared/config.py` 的 `SPIDER_CONFIG` 中新增 `"sonar"` 配置块：`base_url`、`listing_url`、`timeout`、`user_agent`、`queries`（与 Shodan/FOFA queries 同构：`<name> → {query, protocol, sonar_pattern}`）

### 3. Fetch Modal 新增 sonar 选项
- 在 `templates/index.html` 的 `#ipResourceFetchSource` 中新增 `<option value="sonar">Rapid7 Sonar (免费/无需API密钥)</option>`，置于 ipdeny 与 shodan 之间
- 在 `static/script.js` 的 `updateFetchParams()` 中处理 `sonar` source：与 shodan/fofa 一致渲染协议选择 + limit 输入框
- `sonar` 选项**不**显示 "(已配置/未配置)" 徽标（无凭据概念）
- 选中 `sonar` 时「开始获取」按钮始终可点（无告警条、无禁用）

### 4. 升级首次引导提示
- 修改 `#ipResourceFetchOnboardingTip` 提示文案：当 Shodan 与 FOFA 均未配置时，提示条同时推荐免费源
- 新文案："无 API 密钥？可使用 Rapid7 Sonar 免费数据源，或点击「去配置」为 Shodan/FOFA 配置密钥。"
- 提示条按钮新增「切换到免费源」→ 自动将 `#ipResourceFetchSource` 切换到 sonar 并关闭提示条
- 保留原「去配置」「稍后」按钮

## Impact

- **Affected specs**：`add-spider-api-key-onboarding`（互补——在 API 密钥源之外补充免费无密钥源；不修改其已实现行为）
- **Affected code**：
  - 新增 `attack_resources/shared/spiders/sonar_spider.py`
  - 修改 `attack_resources/shared/spiders/__init__.py`（注册 sonar）
  - 修改 `attack_resources/shared/config.py`（新增 sonar 配置块）
  - 修改 `templates/index.html`（`#ipResourceFetchSource` 新增 option；更新 onboarding tip 文案与按钮）
  - 修改 `static/script.js`（`updateFetchParams()` 处理 sonar；onboarding 「切换到免费源」按钮逻辑；refreshCredentialBadges 跳过 sonar 选项）

## ADDED Requirements

### Requirement: Rapid7 Sonar 免费数据源爬虫
系统 SHALL 提供 `sonar` 数据源爬虫，从 Rapid7 OpenData (Project Sonar) 公开下载互联网扫描数据，无需任何 API 密钥或账户。

#### Scenario: 抓取 DNS 协议数据
- **WHEN** 用户在 Fetch Modal 选择 "Rapid7 Sonar" 数据源并选择 "DNS" 协议，limit=500
- **AND** 调用 `fetch_auto_resources("sonar", {"queries": ["dns"], "limit": 500})`
- **THEN** Spider 通过 `requests.get` 抓取 `https://opendata.rapid7.com/sonar.udp/` HTML
- **AND** 用正则匹配文件名形如 `udp_dns_53*.csv.gz` 的最新条目
- **AND** 下载该 `.csv.gz` 到内存，gzip 解压
- **AND** 解析 CSV，提取首列 IP（用正则 `^\d{1,3}(\.\d{1,3}){3}$` 验证），去重，按 limit 截断
- **AND** 写入 `attack_resources/shared/ip_lists/auto/sonar/dns_<YYYYMMDD>.txt`
- **AND** 返回 `{"success": true, "source": "sonar", "files": [{"path": "auto/sonar/dns_<date>.txt", "protocol": "dns", "ip_count": <N>, "source_url": "<downloaded url>"}]}`

#### Scenario: 列表页抓取失败
- **WHEN** `https://opendata.rapid7.com/sonar.udp/` 不可达或返回非 200
- **THEN** Spider 返回 `{"success": false, "error": "无法获取 Sonar 数据集列表: <详情>"}`

#### Scenario: 未匹配到目标协议文件
- **WHEN** HTML 中无任何匹配 `udp_dns_53*.csv.gz` 的文件
- **THEN** 该协议结果中包含 `{"protocol": "dns", "error": "未找到 DNS 对应的 Sonar 数据集文件"}`，其他协议继续处理

#### Scenario: 文件下载或解压失败
- **WHEN** 匹配到的 `.csv.gz` 下载失败或 gzip 解压失败
- **THEN** 该协议结果中包含 `error` 字段，其他协议继续处理

#### Scenario: sonar 不参与凭据状态
- **WHEN** 调用 `GET /api/attack-resource/credentials`
- **THEN** 返回的 `credentials` 字段**不**包含 `sonar` 键（sonar 无凭据概念，不出现在凭据状态中）
- **AND** 后端凭据路由对 `sonar` 作为 source 时返回 400 `{"success": false, "message": "未知的数据源: sonar"}`（保持现有未知 source 行为；sonar 不接受凭据配置）

### Requirement: Sonar 协议到文件名模式映射
系统 SHALL 在 `SPIDER_CONFIG["sonar"]["queries"]` 中定义协议到 Sonar 文件名模式的映射，覆盖现有放大测试支持的协议集。

#### Scenario: 默认协议映射
- **WHEN** 加载 sonar 配置
- **THEN** `queries` 至少包含以下条目（实现时需先在 Sonar 站点核对实际文件名）：
  - `dns` → `{"protocol": "dns", "sonar_pattern": "udp_dns_53"}`
  - `ntp` → `{"protocol": "ntp", "sonar_pattern": "udp_ntp_123"}`
  - `snmp` → `{"protocol": "snmp", "sonar_pattern": "udp_snmp_161"}`
  - `memcached` → `{"protocol": "memcached", "sonar_pattern": "udp_memcached_11211"}`
  - `ssdp` → `{"protocol": "ssdp", "sonar_pattern": "udp_ssdp_1900"}`
- **AND** 若某协议在 Sonar 站点无对应文件，配置中仍保留该条目（运行时按"未匹配文件"场景返回错误，便于将来数据上线即生效）

### Requirement: Fetch Modal sonar 选项
系统 SHALL 在 Fetch Modal 数据源下拉中新增 `sonar` 选项，标注 "免费/无需API密钥"。

#### Scenario: 打开 Fetch Modal 看到 sonar 选项
- **WHEN** 用户打开 Fetch Modal
- **THEN** `#ipResourceFetchSource` 包含 `<option value="sonar">Rapid7 Sonar (免费/无需API密钥)</option>`，位置在 ipdeny 之后、shodan 之前
- **AND** 选中 sonar 时，`#ipResourceFetchParams` 渲染协议选择（DNS/Memcached/NTP/SNMP/SSDP）+ limit 数字输入框（与 shodan/fofa 一致）
- **AND** sonar 选项文本**不**被 `refreshCredentialBadges` 修改（不附加 "(已配置/未配置)" 徽标）
- **AND** 选中 sonar 时 `#ipResourceFetchStart` 按钮 `disabled` 属性为 false（始终可点，不渲染告警条）

### Requirement: 新用户引导提示推荐免费源
当 Shodan 与 FOFA 均未配置时，首次引导提示条 SHALL 同时推荐使用 Rapid7 Sonar 免费源。

#### Scenario: 两 source 均未配置时显示升级版提示
- **WHEN** 用户首次打开 Fetch Modal 且 Shodan 与 FOFA 均未配置
- **AND** `sessionStorage.onboardingTipDismissed !== '1'`
- **THEN** `#ipResourceFetchOnboardingTip` 显示，文案为 "无 API 密钥？可使用 Rapid7 Sonar 免费数据源，或点击「去配置」为 Shodan/FOFA 配置密钥。"
- **AND** 提示条含三个按钮：「切换到免费源」「去配置」「稍后」

#### Scenario: 点击切换到免费源
- **WHEN** 用户点击「切换到免费源」按钮
- **THEN** `#ipResourceFetchSource` 的 value 设置为 "sonar"
- **AND** 触发 `change` 事件以重渲染参数区
- **AND** 隐藏 `#ipResourceFetchOnboardingTip`
- **AND** 写入 `sessionStorage.onboardingTipDismissed = '1'`（本次会话不再显示）

#### Scenario: 任一 source 已配置
- **WHEN** Shodan 或 FOFA 任一已配置
- **THEN** 不显示 `#ipResourceFetchOnboardingTip`（保持原行为）

## MODIFIED Requirements

### Requirement: Fetch Modal 数据源选项展示
**原行为**：`#ipResourceFetchSource` 包含 ipdeny / shodan / fofa 三个选项；Shodan/FOFA 选项文本由 `refreshCredentialBadges` 动态附加 "(已配置/未配置)" 徽标。

**修改为**：`#ipResourceFetchSource` 包含 ipdeny / sonar / shodan / fofa 四个选项。`refreshCredentialBadges` 仅更新 shodan 与 fofa 的选项文本，**不**触碰 ipdeny 与 sonar 的文本（保持其静态文案）。

### Requirement: 首次启动引导提示文案与按钮
**原行为**：两 source 均未配置时显示 "首次使用 Shodan/FOFA？请先配置 API 密钥。" 含「去配置」「稍后」两个按钮。

**修改为**：见上文 "新用户引导提示推荐免费源" 需求——文案改为同时推荐免费源，按钮增至三个（新增「切换到免费源」）。

### Requirement: updateFetchParams 数据源分支
**原行为**：`updateFetchParams()` 对 ipdeny 走国家多选分支；对 shodan/fofa 走协议+limit 分支；其他 source 无处理。

**修改为**：新增 `sonar` 分支，与 shodan/fofa 共用协议+limit 渲染逻辑（可合并为 `if (source === 'shodan' || source === 'fofa' || source === 'sonar')`）。sonar 分支下不渲染凭据告警条、不禁用「开始获取」按钮。

## REMOVED Requirements

无。本变更仅新增 sonar 作为补充免费选项，不移除任何已有功能。
