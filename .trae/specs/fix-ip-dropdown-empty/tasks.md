# Tasks

- [x] Task 1: 修正 `ATTACK_RESOURCES_ROOT` 路径计算
  - [x] SubTask 1.1: 将 `attack_resources/shared/attack_resource_api.py` 第 122 行 `Path(__file__).resolve().parents[2]` 改为 `Path(__file__).resolve().parents[1]`
  - [x] SubTask 1.2: 验证修改后 `list_protocol_resources()` 能正确扫描 `attack_resources/shared/ip_lists/` 目录

- [x] Task 2: 验证四个协议下拉框恢复显示
  - [x] SubTask 2.1: 确认 `/api/attack-resource/tcp/resources` 返回共享池中的 7 个 txt 文件
  - [x] SubTask 2.2: 确认 `/api/attack-resource/dns/resources` 返回相同资源
  - [x] SubTask 2.3: 确认 `/api/attack-resource/memcached/resources` 返回相同资源
  - [x] SubTask 2.4: 确认 `/api/attack-resource/ntp/resources` 返回相同资源

# Task Dependencies

- Task 2 依赖 Task 1 完成
