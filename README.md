## Development Check

克隆项目

```bash
git clone
```

### 编译 ZMap（新设备必须执行）

ZMap 二进制是机器特定的（链接到本机共享库），仓库不再提交预编译二进制。
**每台新设备克隆后必须运行编译脚本**，否则扫描功能会报 exit code 127。

安装编译依赖（只需一次）：

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config \
    libjson-c-dev libpcap-dev libgmp-dev libunistring-dev \
    gengetopt flex byacc
```

编译 ZMap：

```bash
chmod +x build_zmap.sh
./build_zmap.sh
```

> 脚本会自动检测依赖是否已安装：已装则跳过 `sudo apt`，未装则自动安装。
> 如果之前用 `sudo` 编译过导致 `build/` 目录变为 root 所有，脚本会自动用 `sudo rm` 清理。

如果手动清理旧 build 目录：

```bash
rm -rf vendor/weaponizing-censors/zmap/{build,CMakeCache.txt,CMakeFiles} \
       vendor/weaponizing-censors/zmap_multiple_probes/{build,CMakeCache.txt,CMakeFiles}
```

创建虚拟环境，安装必要库

```bash
python -m venv venv
pip install -r requirments.txt
```

启动脚本

```bash
python app.py
```

访问`http://localhost:5000`

### 部署后一键检测（冒烟测试）

只读检查 21 个 API，**不发起任何攻击流量**，可在生产环境随时运行。

```bash
chmod +x scripts/smoke_test.sh
./scripts/smoke_test.sh                          # 默认检测 http://127.0.0.1:5000
./scripts/smoke_test.sh http://127.0.0.1:8000    # 端口不同时指定 BASE_URL
```

检查内容与结果含义：

- `[1] 基础服务`：首页、`/api/system/info`、`/api/config`
- `[2] 服务器 IP 管理`：4 协议的 `/api/servers/<proto>`（含 tcp 文件列表，验证 ip_lists 去重后的共享池回退）
- `[3] 共享资源池 API`：`/api/attack-resource/*`
- `[4] 协议扫描模块`：4 协议扫描端点

结果分三级：

- `OK` —— 接口正常且数据非空
- `WARN` —— 接口正常但返回数据为空。可能是新部署的空资源池（正常），
  也可能是上游依赖故障的隐性传播（如扫描模块损坏导致池子为空），存量部署出现 WARN 建议人工确认数据链路
- `FAIL` —— 接口不可达 / 非 200 / success 不为 true，脚本结尾会按分组给出最可能的根因方向

各项检查相互独立（各自发请求），单项失败不影响其他项判断；存在任一 FAIL 时脚本退出码为 1，可直接用于 CI/部署后自动校验。

> 脚本只能覆盖后端 API 层。前端交互（按钮、表格渲染）请部署后用浏览器点验：
> 各协议扫描页发起一次小扫描 → 观察优质 IP 表格与"一键加入资源池"。

后续切换分支等操作命令示例

```bash
git fetch origin

git reset --hard origin/trae/ui-simplify

git pull origin trae/ui-simplify
```

让AI合并分支时提示词
```bash
请将 feature/xxx 分支合并到 main 分支，要求：
1. 使用 --no-ff 模式合并（非快进合并）
2. 必须创建合并提交（merge commit），保留分支图形结构
3. 不要使用 fast-forward、squash 或 rebase 方式合并
4. 合并提交信息写清楚合并的分支名和功能概述

或

合并 feature/xxx 到 main，用 --no-ff，保留分支线，创建 merge commit，不要 ff/squash/rebase。
```

命令对照
```bash
git checkout main
git merge --no-ff feature/你的分支名
git push
```
