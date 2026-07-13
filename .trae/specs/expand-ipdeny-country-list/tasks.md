# Tasks

- [x] Task 1: 在 `IPDenySpider` 中实现动态抓取全量国家列表
  - [x] SubTask 1.1: 新增 `fetch_country_list()` 方法，请求 `https://www.ipdeny.com/ipblocks/` 并用正则解析页面中所有 `| COUNTRY NAME (CODE) [download [code.zone](...)]` 条目，返回 `[{code, name}, ...]`
  - [x] SubTask 1.2: 新增内存缓存（实例变量 + 时间戳），TTL 从 `config.py` 读取（`country_list_cache_ttl`，默认 86400 秒）；缓存有效期内直接返回缓存
  - [x] SubTask 1.3: 抓取或解析失败时回退到 `self.target_countries`，并记录日志/不抛异常

- [x] Task 2: 修改 `IPDenySpider.fetch()` 与 `get_available_countries()` 使用动态国家列表
  - [x] SubTask 2.1: `fetch()` 中移除 `if country_code not in self.target_countries: continue` 的硬过滤；改为通过动态列表查询国家名，未知代码记为错误项返回
  - [x] SubTask 2.2: `get_available_countries()` 改为返回动态全量列表（调用 `fetch_country_list()`）
  - [x] SubTask 2.3: `fetch()` 中写文件头注释与结果 `country_name` 改为从动态列表查询，动态列表无此代码时回退到 `target_countries`

- [x] Task 3: 修改 `IPResourceManager.get_country_list()` 返回动态全量列表
  - [x] SubTask 3.1: 改为调用 `IPDenySpider().get_available_countries()`，失败时回退到模块级 `COUNTRY_CODES`

- [x] Task 4: 在 `config.py` 中新增 `country_list_cache_ttl` 配置项
  - [x] SubTask 4.1: 在 `ipdeny` 配置块中添加 `"country_list_cache_ttl": 86400`

- [x] Task 5: 调整前端国家多选器默认选中策略
  - [x] SubTask 5.1: `static/script.js` 中 IPdeny 国家的 `<option>` 默认不全选，改为不添加 `selected`（或仅对原常用国家加 `selected`），保留搜索与「全选/取消全选」按钮逻辑

- [ ] Task 6: 验证
  - [x] SubTask 6.1: 启动服务，请求 `/api/attack-resource/resources/countries`，确认返回国家数远大于 14
  - [ ] SubTask 6.2: 在获取弹窗中确认国家列表展示全部国家、默认不全选、搜索/全选功能正常
  - [x] SubTask 6.3: 测试获取一个非硬编码国家（如 `af`）的 zone 文件，确认成功保存

- [x] Task 7: 修复 `fetch_country_list()` 正则以匹配 IPdeny 实际页面 HTML 格式
  - [x] SubTask 7.1: 将 `ipdeny_spider.py` 第 130 行正则改为匹配真实页面格式 `<p>COUNTRY (CODE) [download <a href="...">code.zone</a>]`，确保匹配 200+ 国家
  - [x] SubTask 7.2: 重新运行功能测试确认 `fetch_country_list()` 返回 200+ 国家；重新验证 checklist 项 1、4、10 与 Task 6.1

# Task 6/7 验证说明（正则修复后）
- **SubTask 6.1（通过）**：等价功能测试 `IPDenySpider().fetch_country_list()` 返回 **230** 条，远大于 14。正则修复后不再回退到硬编码 15 个国家。
- **SubTask 6.2（未验证）**：UI 测试，需浏览器手动验证。前端代码审查通过：`script.js` 第 385 行 `<option>` 无 `selected`，搜索/全选/取消全选按钮逻辑完整。
- **SubTask 6.3（通过）**：`fetch_country_list()` 返回 230 条动态列表，`af` 在其中。调用 `fetch({"countries": ["af"]})` 返回 `successful=1`，下载 `af.zone`（133 IP 段），文件保存为 `auto/ipdeny/af_20260713.txt`（测试前手动创建了输出目录）。
- **Task 7.1（通过）**：第 130 行正则替换为 `r"([A-Z][A-Z' ]+?)\s*\(([A-Z]{2})\)\s*\[download\s*<a[^>]*>([a-z]{2})\.zone</a>\]"`，匹配真实 HTML 格式，匹配 230 条。3 捕获组与原解包逻辑兼容，未改动其他代码。
- **Task 7.2（通过）**：功能测试 count=230、has_af=True，checklist 项 1/4/10 均改为 PASS。

# Task Dependencies
- Task 2 依赖 Task 1
- Task 3 依赖 Task 2
- Task 5 可与 Task 1-4 并行
- Task 6 依赖 Task 1-5 全部完成
