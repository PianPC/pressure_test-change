# Tasks

- [x] Task 1: 在 script.js 新增输出文件描述字典与匹配函数
  - [x] SubTask 1.1: 在 `static/script.js` 顶部常量区新增 `OUTPUT_FILE_DESCRIPTIONS` 字典，包含 TCP 的 12 个文件模式（精确 + 前缀/后缀）和 DNS/NTP/Memcached 的 3 个固定文件名（共 15 条）
  - [x] SubTask 1.2: 新增 `getFileDescription(fileName, protocol)` 函数，按"精确匹配 → 后缀匹配 → 前缀匹配"顺序查找，未匹配返回空字符串

- [x] Task 2: 修改三处文件按钮渲染，追加 ℹ️ 图标
  - [x] SubTask 2.1: 修改统一类 `renderArtifacts`（约 L4835-L4851），在按钮 HTML 的 `<span>{name}</span>` 后追加 `<span class="file-info-icon" data-tooltip="{desc}">ℹ️</span>`，并调用 `getFileDescription(artifact.name, protocol)` 获取描述
  - [x] SubTask 2.2: 修改 TCP 旧路径 `renderTcpArtifacts`（约 L1919-L1934），同样追加 ℹ️ 图标，protocol 参数传 "tcp"
  - [x] SubTask 2.3: 修改 DNS 旧路径（约 L4240-L4243），同样追加 ℹ️ 图标，protocol 参数传 "dns"
  - [x] SubTask 2.4: 为 ℹ️ 图标绑定 `click` 事件阻止冒泡（`e.stopPropagation()`），避免点击图标时触发打开文件 modal

- [x] Task 3: 在 style.css 新增 tooltip 样式
  - [x] SubTask 3.1: 新增 `.file-info-icon` 样式（小字号、灰色、cursor:help、与文件名间距）
  - [x] SubTask 3.2: 新增 `.file-info-icon:hover::after` 或 `.file-info-icon[data-tooltip]:hover::after` tooltip 样式，用 `content: attr(data-tooltip)` 显示描述，定位为 absolute，最大宽度 280px，背景/文字色用项目 CSS 变量，z-index 高于按钮
  - [x] SubTask 3.3: 确认 tooltip 不破坏现有 `.tcp-artifact-item` 的 flex 布局（图标用 inline-block，不破坏 space-between）

- [x] Task 4: 验证四协议文件说明显示正确
  - [x] SubTask 4.1: 确认 DNS/NTP/Memcached 的 3 个固定文件（qualified_ips.txt、scan_results.csv、scan_summary.json）hover 时显示对应描述
  - [x] SubTask 4.2: 确认 TCP 的 12 个文件（含动态 stem 和 pkt_method 的文件名）hover 时显示对应描述
  - [x] SubTask 4.3: 确认点击 ℹ️ 图标不触发打开文件 modal
  - [x] SubTask 4.4: 确认未匹配的文件不显示 ℹ️ 图标（或图标隐藏）

# Task Dependencies

- Task 2 依赖 Task 1（渲染时调用 getFileDescription）
- Task 3 与 Task 1/2 相互独立，可并行
- Task 4 依赖 Task 1/2/3 全部完成
