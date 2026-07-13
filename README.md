## Development Check

克隆项目

```bash
git clone
```

确保有cmake
```bash
sudo apt update
sudo apt install -y build-essential cmake libgmp3-dev libpcap-dev libjson-c-dev byacc flex
```

在新设备上编译ZMap

```bash
chmod +x build_zmap.sh
sudo ./build_zmap.sh
```

如果因为没有cmake编译失败
```bash
sudo apt update
sudo apt install -y build-essential cmake libgmp3-dev libpcap-dev libjson-c-dev byacc flex

# 清理旧 build 目录（如果之前有残留）
rm -rf vendor/weaponizing-censors/zmap/{build,CMakeCache.txt,CMakeFiles} vendor/weaponizing-censors/zmap_multiple_probes/{build,CMakeCache.txt,CMakeFiles}

# 再次编译
sudo ./build_zmap.sh
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
