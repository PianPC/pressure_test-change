# Checklist

## 描述字典与匹配函数

- [x] `OUTPUT_FILE_DESCRIPTIONS` 字典包含 TCP 的 12 个文件模式
- [x] `OUTPUT_FILE_DESCRIPTIONS` 字典包含 DNS/NTP/Memcached 的 3 个固定文件名（qualified_ips.txt、scan_results.csv、scan_summary.json）
- [x] `getFileDescription(fileName, protocol)` 函数按"精确 → 后缀 → 前缀"顺序匹配
- [x] 未匹配时返回空字符串（不报错）

## 按钮渲染修改

- [x] 统一类 `renderArtifacts` 的按钮 HTML 包含 `<span class="file-info-icon" data-tooltip="{desc}">ℹ️</span>`
- [x] TCP 旧路径 `renderTcpArtifacts` 的按钮 HTML 包含 ℹ️ 图标
- [x] DNS 旧路径的按钮 HTML 包含 ℹ️ 图标
- [x] ℹ️ 图标绑定了 `click` 事件阻止冒泡（点击图标不打开文件 modal）
- [x] 描述为空时 ℹ️ 图标不显示（或隐藏）

## tooltip 样式

- [x] `.file-info-icon` 样式定义（小字号、灰色、cursor:help）
- [x] tooltip 用 `::after` + `content: attr(data-tooltip)` 实现
- [x] tooltip 最大宽度限制（280px）
- [x] tooltip 背景使用项目 CSS 变量（如 `--bg-elevated`）
- [x] tooltip z-index 高于文件按钮
- [x] tooltip 不破坏 `.tcp-artifact-item` 的 flex 布局

## 四协议验证

- [x] DNS 任务的 qualified_ips.txt / scan_results.csv / scan_summary.json hover 显示描述
- [x] NTP 任务的 3 个文件 hover 显示描述
- [x] Memcached 任务的 3 个文件 hover 显示描述
- [x] TCP 任务的 12 个文件（含动态命名）hover 显示描述
- [x] 点击 ℹ️ 图标不触发打开文件 modal
- [x] 点击按钮其他区域仍正常打开文件 modal
