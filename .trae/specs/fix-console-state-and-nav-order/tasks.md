# Tasks

- [ ] Task 1: 排查控制台"常量状态"问题（待用户提供浏览器错误信息）
  - [ ] SubTask 1.1: 获取浏览器 F12 Console 错误信息
  - [ ] SubTask 1.2: 根据错误信息定位根因并修复

- [x] Task 2: 交换导航栏"资源池"与"攻击资源获取"位置
  - [x] SubTask 2.1: 在 `templates/index.html` 左侧导航栏中，将"资源池"移到"攻击资源获取"之前，步骤编号 01→资源池、02→攻击资源获取
  - [x] SubTask 2.2: 在 `templates/index.html` 流程总览的 `workflow-progress-bar` 中交换卡片顺序，调整编号

- [x] Task 3: 调整前端 JS 工作流顺序常量
  - [x] SubTask 3.1: 在 `static/script.js` 中将 `WORKFLOW_STEP_ORDER` 从 `["resource", "pool", "console", "latency"]` 改为 `["pool", "resource", "console", "latency"]`
  - [x] SubTask 3.2: 检查并调整流程总览相关的文案/推荐逻辑是否需要适配新顺序

- [x] Task 4: 验证导航顺序
  - [x] SubTask 4.1: 确认左侧导航栏顺序为：流程总览 → 资源池(01) → 攻击资源获取(02) → 控制台(03) → 延迟监控(04)
  - [x] SubTask 4.2: 确认流程总览卡片顺序正确
  - [x] SubTask 4.3: 确认流程总览的"推荐下一步"逻辑在新顺序下工作正常

# Task Dependencies

- Task 1 与 Task 2/3/4 独立，可并行
- Task 3 依赖 Task 2（HTML 结构调整后再调整 JS）
- Task 4 依赖 Task 2 和 Task 3 完成
