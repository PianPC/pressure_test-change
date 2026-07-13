# Checklist

## ScanConfig 字段与配置加载

- [x] `ScanConfig` dataclass 中存在 `min_amplification: float = 2.0` 字段
- [x] `ScanConfig` dataclass 中存在 `min_success_rate: float = 50.0` 字段
- [x] `load_config` 能从 TOML `[amplify]` 段读取 `min_amplification`，缺失时回退到默认值 2.0
- [x] `load_config` 能从 TOML `[amplify]` 段读取 `min_success_rate`，缺失时回退到默认值 50.0
- [x] `scan.example.toml` 中包含 `[amplify]` 段及两个字段示例

## runner.py 筛选逻辑与产物格式

- [x] `extract_qualified_ips` 中不再出现 `getattr(cfg, "min_amplification", 2.0)` 兜底写法，改为直接读取 `cfg.min_amplification`
- [x] `extract_qualified_ips` 同时读取 `cfg.min_success_rate` 并传入下游解析函数
- [x] `_parse_amplification_log_for_qualified` 接收 `min_success_rate` 与 `scan_count` 参数
- [x] `success_rate` 计算公式为 `len(ratios) / scan_count * 100`（不再出现 `/ 1.0` 的 bug）
- [x] 筛选条件为 `avg_amp >= min_amplification and success_rate >= min_success_rate` 双阈值
- [x] 筛选结果按 `avg_amp` 降序排序
- [x] `_write_qualified_ips` 每行只写纯 IP，不带 `ratio=`、`success_rate=` 后缀
- [x] `qualified_ips.txt` 头部注释行以 `#` 开头，包含阈值与生成时间

## routes.py 参数接收

- [x] `_config_from_request` 读取 `min_amplification` 并通过 `replace` 写入 `ScanConfig`
- [x] `_config_from_request` 读取 `min_success_rate` 并通过 `replace` 写入 `ScanConfig`
- [x] 前端未传参时使用默认值 2.0 / 50.0（向后兼容）

## 前端 HTML 与 JS

- [x] `templates/index.html` TCP 表单中存在 id 为 `tcpMinAmplification` 的数值输入框，默认值 2.0
- [x] `templates/index.html` TCP 表单中存在 id 为 `tcpMinSuccessRate` 的数值输入框，默认值 50.0
- [x] `static/script.js` 的 TCP `FIELD_MAP` 中存在 `min_amplification` 与 `min_success_rate` 映射
- [x] `readUnifiedTcpForm` 返回的 payload 包含 `min_amplification` 与 `min_success_rate` 字段
- [x] `renderTcpMeta` 在任务详情页显示"最小放大率"与"最小成功率"两行

## 聚合与回归验证

- [x] dry_run 模式下 TCP 任务能正常完成，`qualified_ips.txt` 每行为纯 IP
- [x] `attack_resources/tcp/qualified_pool/qualified_pool.txt` 中均为纯 IP 行（无逗号后缀污染）
- [x] `attack_resources/tcp/resources/ip_lists/qualified_pool.txt` 中均为纯 IP 行
- [x] TCP 任务详情页正确回显当前的 `min_amplification` 与 `min_success_rate` 阈值
