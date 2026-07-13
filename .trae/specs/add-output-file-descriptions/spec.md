# 输出文件作用说明 Spec

## Why

每个协议扫描任务完成后会生成多个输出文件（TCP 12 个、DNS/NTP/Memcached 各 3 个），用户当前只能看到文件名和大小，不知道每个文件的作用。需要在文件按钮旁添加说明图标，hover 时显示该文件的作用描述，帮助用户理解产物内容。

## What Changes

- 在前端 `static/script.js` 新增一份"文件名模式 → 描述"字典，覆盖四个协议的所有输出文件
- 修改文件按钮的渲染逻辑（统一类 `renderArtifacts`、TCP 旧路径 `renderTcpArtifacts`、DNS 旧路径），在每个按钮内追加一个 ℹ️ 图标元素
- 在 `static/style.css` 新增 tooltip 样式（纯 CSS，hover 触发，无需 JS 事件）
- 描述字典采用"精确匹配 + 后缀/前缀模式匹配"策略，兼容 TCP 的动态文件名（含 stem 和 pkt_method）

## Impact

- Affected specs: 无直接相关
- Affected code:
  - [script.js](file:///c:/workplace/project/mi4/pressure_test-change/static/script.js)（新增描述字典、修改三处按钮渲染）
  - [style.css](file:///c:/workplace/project/mi4/pressure_test-change/static/style.css)（新增 tooltip 样式）

## ADDED Requirements

### Requirement: 输出文件作用描述字典

系统 SHALL 在前端维护一份"文件名模式 → 描述"字典，覆盖 TCP、DNS、NTP、Memcached 四个协议的所有输出文件。DNS/NTP/Memcached 用精确文件名匹配（3 个固定文件）；TCP 用精确匹配 + 后缀/前缀模式匹配（兼容含动态 stem 和 pkt_method 的文件名）。

#### Scenario: DNS 文件匹配

- **WHEN** 渲染 DNS 任务的 `qualified_ips.txt` 按钮
- **THEN** 字典精确匹配 `qualified_ips.txt`，返回描述"DNS 优质反射器 IP 列表（放大率达标），每行一个纯 IP"

#### Scenario: TCP 动态文件名匹配

- **WHEN** 渲染 TCP 任务的 `amplification_test_PSH.log` 按钮
- **THEN** 字典通过前缀模式 `amplification_test_*.log` 匹配，返回描述"放大测试阶段日志，记录每个 IP 每次扫描的发送/接收字节数与放大比率"

#### Scenario: 未匹配的文件

- **WHEN** 某文件名在字典中无匹配项（如临时调试文件）
- **THEN** ℹ️ 图标不显示（或显示通用提示"未知文件类型"），不阻塞渲染

### Requirement: 文件按钮说明图标

系统 SHALL 在每个输出文件按钮内追加一个 ℹ️ 图标元素，hover 时通过纯 CSS tooltip 显示该文件的作用描述。图标不干扰按钮原有的点击打开文件行为。

#### Scenario: hover 显示说明

- **WHEN** 用户鼠标悬停在 ℹ️ 图标上
- **THEN** 图标下方/右侧浮出一个 tooltip，显示该文件的作用描述
- **AND** tooltip 不遮挡文件名和大小
- **AND** 鼠标移开后 tooltip 消失

#### Scenario: 点击图标不触发文件打开

- **WHEN** 用户点击 ℹ️ 图标（非按钮其他区域）
- **THEN** 不触发打开文件 modal 的行为（阻止事件冒泡）

### Requirement: tooltip 样式

系统 SHALL 在 `static/style.css` 新增 tooltip 样式，与现有 UI 风格一致（使用项目既有的 CSS 变量如 `--text-primary`、`--bg-elevated` 等）。

#### Scenario: 样式一致性

- **WHEN** tooltip 显示
- **THEN** 背景使用 `--bg-elevated` 或 `--bg-secondary`，文字使用 `--text-primary`，圆角、阴影与现有 modal/卡片风格一致
- **AND** tooltip 最大宽度限制（如 280px），避免过长描述撑破布局
- **AND** z-index 高于文件按钮（避免被遮挡）

## MODIFIED Requirements

### Requirement: 文件按钮渲染

文件按钮 HTML 结构在原有 `<span>{name}</span><strong>{size}</strong>` 基础上，在文件名后追加 `<span class="file-info-icon" data-tooltip="{description}">ℹ️</span>`。三处渲染入口（统一类 `renderArtifacts`、TCP 旧路径 `renderTcpArtifacts`、DNS 旧路径）均需修改。
