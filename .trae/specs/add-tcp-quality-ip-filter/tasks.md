# Tasks

- [x] Task 1: 在 TCP ScanConfig 中新增筛选配置字段
  - [x] SubTask 1.1: 在 `attack_resources/tcp/code/tcp_censor_scan/config.py` 的 `ScanConfig` dataclass 中新增 `min_amplification: float = 2.0` 与 `min_success_rate: float = 50.0` 两个字段（注意 frozen=True 的写法）
  - [x] SubTask 1.2: 在 `load_config` 函数中增加从 TOML `[amplify]` 段读取 `min_amplification` 与 `min_success_rate` 的逻辑，缺失时使用默认值
  - [x] SubTask 1.3: 在 `attack_resources/tcp/config/scan.example.toml` 中补充 `[amplify]` 段及两个字段示例值

- [x] Task 2: 修复 TCP runner.py 的筛选逻辑与产物格式
  - [x] SubTask 2.1: 修改 `extract_qualified_ips`，将 `getattr(cfg, "min_amplification", 2.0)` 改为直接读取 `cfg.min_amplification`，并传入 `cfg.min_success_rate`
  - [x] SubTask 2.2: 修改 `_parse_amplification_log_for_qualified`，增加 `min_success_rate` 参数与 `scan_count` 参数，修复 `success_rate` 计算 bug（`len(ratios) / scan_count * 100`），在返回结果中按 `avg_amp >= min_amplification and success_rate >= min_success_rate` 双阈值过滤，并按 `avg_amp` 降序排序
  - [x] SubTask 2.3: 修改 `_write_qualified_ips`，每行只写纯 IP，头部注释保留阈值与生成时间信息（参考 DNS 的 `qualified_ips.txt` 写法）

- [x] Task 3: 在 TCP 路由层接收前端筛选参数
  - [x] SubTask 3.1: 在 `attack_resources/tcp/code/routes.py` 的 `_config_from_request` 中读取 `min_amplification` 与 `min_success_rate`，用 `_float_or` 兜底默认值（2.0 / 50.0），并通过 `replace(...)` 写入 `ScanConfig`
  - [x] SubTask 3.2: 若 `_float_or` 辅助函数在 TCP routes.py 中不存在，则新增（参考 DNS routes.py 的实现）

- [x] Task 4: 在前端 HTML 与 JS 中补齐 TCP 筛选输入框
  - [x] SubTask 4.1: 在 `templates/index.html` 的 TCP 表单区域（L236-L305 附近）新增"最小放大率"与"最小成功率"两个数值输入框，id 分别为 `tcpMinAmplification`（默认 2.0，min=0 max=100 step=0.1）与 `tcpMinSuccessRate`（默认 50.0，min=0 max=100 step=1）
  - [x] SubTask 4.2: 在 `static/script.js` 的 TCP `FIELD_MAP` 中增加 `min_amplification: "#tcpMinAmplification"` 与 `min_success_rate: "#tcpMinSuccessRate"` 两个映射
  - [x] SubTask 4.3: 在 `static/script.js` 的 `readUnifiedTcpForm` 中增加 `min_amplification` 与 `min_success_rate` 两个字段的读取（用 `parseFloat(...) || 默认值` 兜底）
  - [x] SubTask 4.4: 在 `static/script.js` 的 `renderTcpMeta` 中增加"最小放大率"与"最小成功率"两行回显（参考 DNS 的 `renderDnsMeta` 实现）

- [x] Task 5: 验证与回归测试
  - [x] SubTask 5.1: 在 dry_run 模式下启动一次 TCP 扫描任务，确认 `qualified_ips.txt` 每行为纯 IP，头部注释包含阈值信息
  - [x] SubTask 5.2: 确认 `scan_summary.json`（或 TCP 对应的 metadata/summary）中记录了 `min_amplification` 与 `min_success_rate` 阈值
  - [x] SubTask 5.3: 确认任务完成后 `attack_resources/tcp/qualified_pool/qualified_pool.txt` 与 `attack_resources/tcp/resources/ip_lists/qualified_pool.txt` 中均为纯 IP 行（无 `ratio=`、`success_rate=` 污染）

# Task Dependencies

- Task 2 依赖 Task 1（runner.py 需要 ScanConfig 的新字段）
- Task 3 依赖 Task 1（routes.py 通过 `replace` 写入新字段，需要 ScanConfig 先支持）
- Task 4 与 Task 1/2/3 相互独立，可并行进行（前端字段名与后端对齐即可）
- Task 5 依赖 Task 1/2/3/4 全部完成
