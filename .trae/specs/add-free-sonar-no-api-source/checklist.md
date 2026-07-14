# Checklist

## 配置与注册
- [x] `attack_resources/shared/config.py` 的 `SPIDER_CONFIG` 含 `"sonar"` 键，包含 `base_url` / `listing_url` / `timeout` / `user_agent` / `queries`
- [x] `queries` 至少包含 dns / ntp / snmp / memcached / ssdp 五个协议，每个含 `protocol` 与 `sonar_pattern`
- [x] `sonar_pattern` 值已通过实际访问 `https://opendata.rapid7.com/sonar.udp/` 核实存在 — DNS=`udp_dns_53`✅、NTP=`udp_ntpmonlist_123`✅（原 spec 假设 `udp_ntp_123` 有误，已修正）、Memcached=`udp_memcached_11211`✅、SSDP=`udp_upnp_1900`✅（原 spec 假设 `udp_ssdp_1900` 有误，已修正）、SNMP=`udp_snmp_161`⚠️（1-3 页未见，保留配置待将来上线）。注：所有 pattern 仅在列表页可见，实际下载被 Rapid7 商业授权 gated。
- [x] `attack_resources/shared/spiders/__init__.py` 的 `SPIDERS` 字典含 `"sonar": SonarSpider`

## SonarSpider 实现
- [x] `attack_resources/shared/spiders/sonar_spider.py` 存在并定义 `SonarSpider` 类
- [x] `__init__` 从 `SPIDER_CONFIG["sonar"]` 读取配置，**不**调用 `credential_store`
- [x] `fetch(params)` 抓取 `listing_url` HTML 并用正则提取 `.csv.gz` 文件名
- [x] listing 不可达时返回 `{"success": false, "error": "无法获取 Sonar 数据集列表: ..."}`
- [x] 对每个 query 按 `sonar_pattern` 过滤文件名，取最新一个（按文件名日期前缀排序）
- [x] 未匹配文件时该协议结果含 `error` 字段，其他协议继续
- [x] 下载 `.csv.gz` 后 gzip 解压，按行解析首列 IP，用正则 `^\d{1,3}(\.\d{1,3}){3}$` 校验，去重，按 limit 截断
- [x] 输出文件写入 `ip_lists/auto/sonar/<protocol>_<YYYYMMDD>.txt`，含文件头注释（Source / Fetch time / Total results）
- [x] 返回结构含 `success` / `source: "sonar"` / `files` / `total_queries` / `successful`
- [x] `get_available_queries()` 返回 `[{name, protocol, sonar_pattern}]`

## Fetch Modal sonar 选项
- [x] `templates/index.html` 的 `#ipResourceFetchSource` 含 `<option value="sonar">Rapid7 Sonar (免费/无需API密钥)</option>`，位于 ipdeny 与 shodan 之间
- [x] `static/script.js` 的 `updateFetchParams()` 对 `sonar` 走协议+limit 分支（与 shodan/fofa 共用）
- [x] `startFetch()` 对 `sonar` 构造 params `{queries, limit}` 并调用 `fetchAutoResources('sonar', params)`
- [x] `refreshCredentialBadges()` 不修改 sonar 选项文本（保持静态 "Rapid7 Sonar (免费/无需API密钥)"）
- [x] 选中 sonar 时不渲染红色告警条、不禁用 `#ipResourceFetchStart` 按钮

## 首次引导提示升级
- [x] `#ipResourceFetchOnboardingTip` 文案为 "无 API 密钥？可使用 Rapid7 Sonar 免费数据源，或点击「去配置」为 Shodan/FOFA 配置密钥。"
- [x] 提示条含三个按钮：「切换到免费源」「去配置」「稍后」
- [x] `#onboardingUseSonar` click → 设置 `#ipResourceFetchSource.value = 'sonar'` + 触发 change + 隐藏提示条 + 写 sessionStorage
- [x] 「去配置」「稍后」按钮保留原行为
- [x] 任一 source（shodan/fofa）已配置时不显示提示条

## 后端凭据路由兼容
- [x] `GET /api/attack-resource/credentials` 返回的 `credentials` 不含 `sonar` 键（已验证：`{credentials: {fofa, shodan}, success: true}`）
- [x] `POST /api/attack-resource/credentials/sonar` 返回 400（已验证：`{message: "未知的数据源: sonar", success: false}`）

## 端到端验证
- [x] `SPIDERS` 含 sonar（已验证：`['ipdeny', 'shodan', 'fofa', 'sonar']`）
- [ ] 直接调用 `SonarSpider().fetch({"queries": ["dns"], "limit": 50})` 返回 `success: true` 且文件生成 — **受阻**：Rapid7 OpenData 已商业化，下载被 gated 返回 HTML 而非 gzip，Spider 优雅降级返回 error
- [ ] 生成的 txt 文件首列为合法 IP，行数 ≤ limit — **受阻**：同上，无文件生成
- [x] `GET /credentials` 不含 sonar 键（已验证）
- [x] `POST /credentials/sonar` 返回 400（已验证）
- [ ] 浏览器：sonar 选项可见 → 选中 → 无告警条按钮可点 → 开始获取成功 — 待用户在浏览器确认（前端代码已就位，JS 语法检查通过）
- [ ] 浏览器：Shodan/FOFA 均未配置时看到三按钮提示条 → 「切换到免费源」生效 — 待用户在浏览器确认
