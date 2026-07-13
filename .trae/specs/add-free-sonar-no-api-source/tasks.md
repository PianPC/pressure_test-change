# Tasks

- [x] Task 1: 核实 Sonar 文件名模式并新增配置
  - [x] SubTask 1.1: WebFetch `https://opendata.rapid7.com/sonar.udp/?page=2` 与 `?page=3`，搜索是否存在 `udp_dns_53`、`udp_ntp_123`、`udp_snmp_161`、`udp_memcached_11211`、`udp_ssdp_1900` 文件名（如不存在则查找实际命名）
  - [x] SubTask 1.2: 在 `attack_resources/shared/config.py` 的 `SPIDER_CONFIG` 中新增 `"sonar"` 配置块：`base_url`、`listing_url` (`https://opendata.rapid7.com/sonar.udp/`)、`timeout` (60)、`user_agent` ("Mozilla/5.0")、`queries` 字典（每个协议含 `protocol` + `sonar_pattern`）
  - [x] SubTask 1.3: 在 `attack_resources/shared/spiders/__init__.py` 的 `SPIDERS` 字典中导入并注册 `"sonar": SonarSpider`

- [x] Task 2: 实现 SonarSpider
  - [x] SubTask 2.1: 新建 `attack_resources/shared/spiders/sonar_spider.py`，实现 `SonarSpider` 类，`__init__` 从 `SPIDER_CONFIG["sonar"]` 读取配置（无凭据加载）
  - [x] SubTask 2.2: 实现 `fetch(params)`：解析 `queries` 与 `limit`，抓取 `listing_url` HTML，用正则 `<a href="([^"]+\.csv\.gz)">` 提取文件名列表
  - [x] SubTask 2.3: 对每个 query，用 `sonar_pattern` 过滤文件名，取最新（按文件名日期前缀排序）一个，构造下载 URL `https://opendata.rapid7.com/<href>`
  - [x] SubSubTask 2.3.1: 若 listing 不可达或非 200，整体返回 `{"success": false, "error": "无法获取 Sonar 数据集列表: <详情>"}`
  - [x] SubTask 2.4: 下载 `.csv.gz` 到内存，`gzip.decompress` 解压，按行解析 CSV 取首列，用正则 `^\d{1,3}(\.\d{1,3}){3}$` 校验 IP，去重，按 limit 截断
  - [x] SubTask 2.5: 写入 `attack_resources/shared/ip_lists/auto/sonar/<protocol>_<YYYYMMDD>.txt`，文件头含 `# Sonar - <protocol> servers`、`# Source: <downloaded url>`、`# Fetch time: <ISO>`、`# Total results: <N>`
  - [x] SubTask 2.6: 返回结构 `{"success": true, "source": "sonar", "files": [...], "total_queries": N, "successful": M}`，单协议失败在 files 元素中含 `error`
  - [x] SubTask 2.7: 实现 `get_available_queries()` 返回 `[{name, protocol, sonar_pattern}]`

- [x] Task 3: Fetch Modal 新增 sonar 选项
  - [x] SubTask 3.1: 在 `templates/index.html` 的 `#ipResourceFetchSource` 中，在 ipdeny option 之后、shodan option 之前插入 `<option value="sonar">Rapid7 Sonar (免费/无需API密钥)</option>`
  - [x] SubTask 3.2: 在 `static/script.js` 的 `updateFetchParams()` 中，将 `source === 'shodan' || source === 'fofa'` 分支扩展为 `source === 'shodan' || source === 'fofa' || source === 'sonar'`，复用协议+limit 渲染逻辑
  - [x] SubTask 3.3: 在 `startFetch()` 中，将 `source === 'shodan' || source === 'fofa'` 的 params 构造分支扩展为含 `sonar`
  - [x] SubTask 3.4: 在 `refreshCredentialBadges()` 中确认**不**修改 sonar 选项文本（仅 shodan/fofa），保持 sonar 静态文案

- [x] Task 4: 升级首次引导提示
  - [x] SubTask 4.1: 在 `templates/index.html` 修改 `#ipResourceFetchOnboardingTip` 文案为 "无 API 密钥？可使用 Rapid7 Sonar 免费数据源，或点击「去配置」为 Shodan/FOFA 配置密钥。"
  - [x] SubTask 4.2: 在 `#ipResourceFetchOnboardingTip` 内新增 `<button id="onboardingUseSonar">切换到免费源</button>`，置于「去配置」之前
  - [x] SubTask 4.3: 在 `static/script.js` 绑定 `#onboardingUseSonar` click：设置 `#ipResourceFetchSource.value = 'sonar'`，触发 `change` 事件，隐藏提示条，写 `sessionStorage.onboardingTipDismissed = '1'`

- [x] Task 5: 端到端验证
  - [x] SubTask 5.1: SPIDERS 已含 sonar（`python -c "from attack_resources.shared.spiders import SPIDERS; print(list(SPIDERS.keys()))"` 返回 `['ipdeny', 'shodan', 'fofa', 'sonar']`）
  - [ ] SubTask 5.2: 调用 `SonarSpider().fetch({"queries": ["dns"], "limit": 50})` 返回 `success: true` 且文件生成 — **受阻**：Rapid7 OpenData 已商业化，下载被 gated 返回 HTML 而非 gzip，Spider 优雅降级返回 error。代码架构正确，待 Rapid7 开放或切换数据源后即可工作。
  - [ ] SubTask 5.3: 验证生成的 txt 文件 — **受阻**：同上，无文件生成
  - [x] SubTask 5.4: `GET /credentials` 不含 sonar 键（已验证：response 为 `{credentials: {fofa, shodan}, success: true}`，无 sonar）
  - [x] SubTask 5.5: `POST /credentials/sonar` 返回 400（已验证：`{message: "未知的数据源: sonar", success: false}`，HTTP 400）
  - [ ] SubTask 5.6: 浏览器手动验证 sonar 选项可见 + 可点 — 待用户在浏览器确认
  - [ ] SubTask 5.7: 浏览器手动验证三按钮提示条 — 待用户在浏览器确认

# Task Dependencies

- Task 2 依赖 Task 1（Spider 实现依赖配置与注册）
- Task 3 依赖 Task 2（Fetch Modal 选项依赖后端 spider 已注册）
- Task 4 依赖 Task 3（提示条升级依赖 sonar 选项已存在）
- Task 5 依赖 Task 1-4 全部完成
- Task 1 的 SubTask 1.1（核实文件名）必须先完成，SubTask 1.2/1.3 才能写入正确配置
