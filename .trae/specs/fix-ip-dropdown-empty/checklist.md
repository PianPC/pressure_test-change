# Checklist

- [x] `attack_resource_api.py` 第 122 行 `ATTACK_RESOURCES_ROOT` 改为 `parents[1]`
- [x] 修改后 `list_protocol_resources()` 能正确扫描 `attack_resources/shared/ip_lists/` 目录
- [x] 四个协议的 `/api/attack-resource/{proto}/resources` 接口返回共享池中的资源（非空列表）
- [x] 四个协议的"IP资源"下拉框不再显示"暂无可用IP资源"
