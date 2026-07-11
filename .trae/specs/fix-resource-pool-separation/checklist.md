# Checklist

## 后端：IP 资源下拉框数据源

- [ ] `list_protocol_resources()` 不再调用 `legacy_resource_roots()`，仅扫描 `shared/ip_lists/`
- [ ] 四个协议的 `/api/attack-resource/{proto}/resources` 接口返回内容仅来自共享池
- [ ] 各协议"IP资源"下拉框展示的资源与"资源管理"模态框完全一致
- [ ] `attack_resources/{proto}/resources/ip_lists/` 等 legacy 目录中的文件不再出现在下拉框

## 后端：协议独立质量 IP 池

- [ ] `attack_resources/tcp/qualified_pool/` 目录已创建
- [ ] `attack_resources/dns/qualified_pool/` 目录已创建
- [ ] `attack_resources/memcached/qualified_pool/` 目录已创建
- [ ] `attack_resources/ntp/qualified_pool/` 目录已创建
- [ ] `attack_resources/shared/qualified_pool.py` 模块已创建，包含 `aggregate_quality_ips()` 和 `list_qualified_pool_ips()` 函数
- [ ] `aggregate_quality_ips()` 正确实现：读取任务产物 → 合并现有池 → 去重 → 写回
- [ ] `list_qualified_pool_ips()` 正确返回指定协议质量 IP 池的 IP 列表及统计信息

## 后端：扫描完成聚合逻辑

- [ ] TCP 扫描任务完成后调用 `aggregate_quality_ips('tcp', ...)`
- [ ] DNS 扫描任务完成后调用 `aggregate_quality_ips('dns', ...)`
- [ ] Memcached 扫描任务完成后调用 `aggregate_quality_ips('memcached', ...)`
- [ ] NTP 扫描任务完成后调用 `aggregate_quality_ips('ntp', ...)`
- [ ] 任务日志中记录"已聚合到质量 IP 池"提示

## 后端：资源池数据源切换

- [ ] `app.py` 中 `list_server_sources(method)` 改为调用 `list_qualified_pool_ips(method)`
- [ ] `/api/servers/<method>` 返回结构包含 IP 列表、总数、地理分布统计
- [ ] 空 quality IP 池时返回 `ips: [], total: 0` 而非报错

## 前端：资源池页面

- [ ] 切换协议标签时调用 `/api/servers/<method>` 获取该协议独立质量 IP
- [ ] 地理分布地图数据源正确切换为协议独立质量 IP 池
- [ ] 统计卡片展示该协议独立质量 IP 的数量
- [ ] 空质量 IP 池时展示友好提示文案
- [ ] 资源池页面文案明确"展示各协议扫描产出的质量 IP"

## 端到端验证

- [ ] 执行一次扫描任务后，`attack_resources/{proto}/qualified_pool/qualified_pool.txt` 正确生成/更新
- [ ] 资源池页面对应协议标签展示的是该协议独立的质量 IP
- [ ] 切换不同协议标签，展示的 IP 集合不同（协议隔离生效）
- [ ] 在"资源管理"手动添加/爬取新 IP 资源后，四个协议的"IP资源"下拉框均能看到新资源
- [ ] 不同协议的"IP资源"下拉框内容一致（均来自共享池）
