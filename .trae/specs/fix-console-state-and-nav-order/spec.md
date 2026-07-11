# 控制台状态与导航顺序调整 Spec

## Why

用户反馈两个问题：
1. 控制台现在处于"常量状态"——经全面排查，后端 API（`/api/config`、`/api/servers/*`、`/api/attack-resource/*`）全部正常返回 200，前端 `static/script.js` 通过 `node --check` 语法校验无错误。代码层面未定位到根因，需要用户提供浏览器 DevTools Console 的错误信息或截图来进一步定位。
2. 用户希望交换左侧导航栏和流程总览中"攻击资源获取"与"资源池"的位置——用户先查看是否有足够资源（资源池），然后才决定是否获取新的攻击资源。

## What Changes

### 问题 1：控制台常量状态（待用户提供更多信息）
- 当前状态：已排查后端 API、前端语法、初始化链路，均未发现异常
- 需要用户提供：浏览器 F12 → Console 标签页的红色错误信息，或 Network 标签页中 `/api/config` 请求的状态码和响应

### 问题 2：交换导航顺序
- 在 `templates/index.html` 中交换左侧导航栏"攻击资源获取"（步骤 1）和"资源池"（步骤 2）的位置
- 在流程总览的 `workflow-progress-bar` 中交换对应卡片顺序
- 调整步骤编号显示（资源池变为 01，攻击资源获取变为 02）
- 调整 `static/script.js` 中的 `WORKFLOW_STEP_ORDER` 常量顺序
- 调整 `VIEW_TO_WORKFLOW_STEP` 映射（如需要）

## Impact

- Affected code:
  - `templates/index.html`（导航栏 + 流程总览卡片）
  - `static/script.js`（`WORKFLOW_STEP_ORDER` 常量）

## ADDED Requirements

### Requirement: 导航顺序反映用户操作流程
系统 SHALL 将"资源池"作为流程第一步（01），"攻击资源获取"作为流程第二步（02），因为用户先查看现有资源再决定是否获取新资源。

#### Scenario: 导航栏顺序
- **WHEN** 用户查看左侧导航栏
- **THEN** 顺序为：流程总览 → 资源池(01) → 攻击资源获取(02) → 控制台(03) → 延迟监控(04)

#### Scenario: 流程总览卡片顺序
- **WHEN** 用户查看流程总览页面
- **THEN** 步骤卡片顺序为：资源池(01) → 攻击资源获取(02) → 控制台(03) → 延迟监控(04)

## MODIFIED Requirements

### Requirement: WORKFLOW_STEP_ORDER
**原行为**：`["resource", "pool", "console", "latency"]`

**修改为**：`["pool", "resource", "console", "latency"]`

## REMOVED Requirements

（无）
