# Checklist

- [x] `IPDenySpider.fetch_country_list()` 能从 `https://www.ipdeny.com/ipblocks/` 解析出 200+ 个国家（code + name）
- [x] 国家列表在 TTL 内被缓存，不重复回源 IPdeny 网站
- [x] IPdeny 网站不可达时，`get_available_countries()` 与 `get_country_list()` 回退到 `config.py` 的 `target_countries`，接口不报 500
- [x] `IPDenySpider.fetch()` 不再因「国家不在 `target_countries`」而跳过；非硬编码国家（如 `af`）可成功下载并保存 zone 文件
- [x] 传入 IPdeny 网站上不存在的国家代码时，该国家在结果中标记为错误，不影响其他有效国家
- [x] `IPResourceManager.get_country_list()` 返回动态全量列表，而非硬编码 14 个
- [x] `config.py` 中 `ipdeny` 配置块含 `country_list_cache_ttl` 配置项
- [x] 前端获取弹窗的国家多选器展示全部国家，默认不全选 200+ 国家
- [x] 前端搜索框、「全选/取消全选」按钮在全量列表下功能正常
- [x] 资源获取页面的国家选择列表大小显著大于 14

# 验证说明（Verification Notes）

## 功能测试结果（Task 7.1 正则修复后重新验证）
- 实际请求 `https://www.ipdeny.com/ipblocks/`：HTTP 200，网络正常。
- 使用修复后的正则 `r"([A-Z][A-Z' ]+?)\s*\(([A-Z]{2})\)\s*\[download\s*<a[^>]*>([a-z]{2})\.zone</a>\]"` 匹配页面。
- 调用 `IPDenySpider().fetch_country_list()`：返回 **230** 条（去重排序后），非硬编码回退。
- `has_af=True`（Afghanistan，非硬编码国家）。
- 调用 `IPDenySpider().fetch({'countries':['af']})`：`successful=1`，下载 `af.zone` 含 133 个 IP 段，文件保存为 `auto/ipdeny/af_20260713.txt`。

## 修复内容（Task 7.1）
**仅替换 `ipdeny_spider.py` 第 130 行的 `pattern = ...`。**

旧正则（假设 markdown 表格格式，匹配 0 条）：
`r"\|\s*([A-Z' ]+?)\s*\(([A-Z]{2})\)\s*\[download\s*\[([a-z]{2})\.zone\]"`

新正则（匹配真实 HTML 格式，匹配 230 条）：
`r"([A-Z][A-Z' ]+?)\s*\(([A-Z]{2})\)\s*\[download\s*<a[^>]*>([a-z]{2})\.zone</a>\]"`

不严格要求 `<p>` 前缀，锚定「大写国家名 + `(CODE)` + `[download <a...>code.zone</a>]`」特征；3 个捕获组与原 `for name_raw, _upper_code, lower_code in matches:` 解包保持兼容。`-aggregated.zone` 等条目因 `([a-z]{2})\.zone` 严格匹配 2 字母代码而被排除。

## 各检查点结论
- **项 1（解析 200+）PASS**：正则匹配 230 条，远超 200。
- **项 2（缓存）PASS**：`_country_list_cache` / `_country_list_cache_ts` 与 TTL 判断逻辑正确（代码审查）。
- **项 3（回退）PASS**：`fetch_country_list()` try/except 回退到 `target_countries`；`get_country_list()` try/except 回退到 `COUNTRY_CODES`。
- **项 4（fetch 不跳过 + af 可用）PASS**：硬过滤已移除；`af` 在动态 `country_map` 中命中，成功下载并保存 zone 文件（133 IP 段）。
- **项 5（未知代码标记 error 不影响其他）PASS**：error 分支 append 后 `continue`，逻辑正确。
- **项 6（get_country_list 返回动态列表）PASS**：代码已调用 `IPDenySpider().get_available_countries()`，现返回 230 条动态列表。
- **项 7（配置项）PASS**：`config.py` 第 25 行 `"country_list_cache_ttl": 86400` 存在。
- **项 8（前端不全选）PASS**：`script.js` 第 385 行 `<option>` 未添加 `selected`（代码审查）。
- **项 9（搜索/全选/取消全选）PASS**：`updateFetchParams()` 中搜索 input 监听、`ipResourceSelectAll`、`ipResourceDeselectAll` 按钮逻辑完整（代码审查）。
- **项 10（列表大小显著 > 14）PASS**：实际返回 230 条，显著大于 14。

## 局限性
- 项 8、项 9（前端 UI）仅代码审查，未做浏览器手动验证（对应 SubTask 6.2）。
- af 下载测试前需手动创建输出目录 `attack_resources/shared/ip_lists/auto/ipdeny/`（fetch 逻辑未自动建目录，非本次修复范围）。
