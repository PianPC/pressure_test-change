#!/bin/bash

# 压力测试工具启动脚本

echo "========================================="
echo "    压力测试工具 - 启动脚本"
echo "========================================="
echo ""

# 检查Python版本
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "✓ Python版本: $python_version"

# 检查依赖
echo ""
echo "检查依赖..."
pip3 install -r requirements.txt

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
    echo ""
    echo "⚠️  警告: 推荐使用root权限运行"
    echo "  某些功能可能需要root权限"
    echo "  可以使用: sudo ./start.sh"
    echo ""
fi

# 创建必要目录
echo ""
echo "创建目录..."
mkdir -p servers static templates

# 复制模板文件（如果不存在）
if [ ! -f "templates/index.html" ]; then
    echo "复制模板文件..."
    cp -r templates_example/* templates/ 2>/dev/null || true
fi

# 启动应用
echo ""
echo "启动应用..."
echo "访问地址: http://localhost:5000"
echo ""
echo "按 Ctrl+C 停止服务"
echo ""

python3 app.py