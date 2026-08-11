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
