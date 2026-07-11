# 修复 IP 资源下拉框显示"暂无可用IP资源" Spec

## Why

上一轮"修复资源池协议隔离"后，四个协议（TCP/Memcached/NTP/DNS）的"IP资源"下拉框全部显示"暂无可用IP资源"。根因是 `attack_resource_api.py` 中的 `ATTACK_RESOURCES_ROOT` 路径计算错误：`Path(__file__).resolve().parents[2]` 指向项目根目录（如 `c:\workplace\project\mi4\pressure_test-change`），而非 `attack_resources` 目录。导致 `shared_ip_root()` 拼出 `项目根/shared/ip_lists`（不存在），实际路径应为 `项目根/attack_resources/shared/ip_lists`。此 bug 之前被 legacy 目录扫描掩盖，移除 legacy 扫描后暴露。

## What Changes

- 修正 `attack_resource_api.py` 第 122 行 `ATTACK_RESOURCES_ROOT` 从 `parents[2]`（项目根）改为 `parents[1]`（`attack_resources` 目录）
- 该常量仅被 `_list_protocol_resources()` 和 `_resolve_protocol_resource()` 使用，修改后两者路径解析均修正

## Impact

- Affected code: `attack_resources/shared/attack_resource_api.py`（第 122 行单行修改）

## ADDED Requirements

（无）

## MODIFIED Requirements

### Requirement: ATTACK_RESOURCES_ROOT 路径正确性
**原行为**：`ATTACK_RESOURCES_ROOT = Path(__file__).resolve().parents[2]`，解析为项目根目录，导致 `shared_ip_root()` 拼出错误路径 `项目根/shared/ip_lists`。

**修改为**：`ATTACK_RESOURCES_ROOT = Path(__file__).resolve().parents[1]`，解析为 `attack_resources` 目录，`shared_ip_root()` 正确拼出 `attack_resources/shared/ip_lists`。

## REMOVED Requirements

（无）
