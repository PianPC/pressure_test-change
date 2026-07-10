## Development Check

克隆项目

```bash
git clone
```

在新设备上编译ZMap

```bash
chmod +x build_zmap.sh
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
