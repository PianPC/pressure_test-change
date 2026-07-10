#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info "========================================"
print_info "    压力测试工具 - 环境初始化脚本"
print_info "========================================"
print_info ""

if [ "$EUID" -ne 0 ]; then 
    print_warn "建议使用root权限运行"
    print_warn "某些功能（如zmap编译）需要root权限"
    print_warn "可以使用: sudo ./setup.sh"
    print_info ""
fi

print_info "1. 检查并安装系统依赖..."
if [ -f /etc/debian_version ]; then
    print_info "检测到 Debian/Ubuntu/Kali 系统"
    print_info "更新软件源..."
    apt-get update -y
    
    print_info "安装编译依赖..."
    apt-get install -y build-essential cmake libgmp3-dev libpcap-dev libjson-c-dev byacc flex traceroute
elif [ -f /etc/redhat-release ]; then
    print_info "检测到 RHEL/CentOS/Fedora 系统"
    print_info "安装编译依赖..."
    yum install -y gcc gcc-c++ cmake gmp-devel libpcap-devel json-c-devel byacc flex traceroute
else
    print_warn "无法识别系统类型，请手动安装以下依赖："
    print_warn "  build-essential cmake libgmp3-dev libpcap-dev libjson-c-dev byacc flex traceroute"
fi

print_info ""
print_info "2. 编译 ZMap (single_probe)..."
ZMAP_SINGLE="vendor/weaponizing-censors/zmap"
ZMAP_SINGLE_BUILD="${ZMAP_SINGLE}/build"
ZMAP_SINGLE_BIN="${ZMAP_SINGLE_BUILD}/src/zmap"

if [ -f "$ZMAP_SINGLE_BIN" ]; then
    print_info "ZMap (single_probe) 已编译，跳过..."
else
    print_info "创建build目录..."
    mkdir -p "$ZMAP_SINGLE_BUILD"
    cd "$ZMAP_SINGLE_BUILD"
    
    print_info "运行cmake..."
    cmake ..
    
    print_info "编译中（这可能需要几分钟）..."
    make -j$(nproc)
    
    cd - > /dev/null
    
    if [ -f "$ZMAP_SINGLE_BIN" ]; then
        print_info "ZMap (single_probe) 编译成功!"
    else
        print_error "ZMap (single_probe) 编译失败!"
        exit 1
    fi
fi

print_info ""
print_info "3. 编译 ZMap (multiple_probes)..."
ZMAP_MULTI="vendor/weaponizing-censors/zmap_multiple_probes"
ZMAP_MULTI_BUILD="${ZMAP_MULTI}/build"
ZMAP_MULTI_BIN="${ZMAP_MULTI_BUILD}/src/zmap"

if [ -f "$ZMAP_MULTI_BIN" ]; then
    print_info "ZMap (multiple_probes) 已编译，跳过..."
else
    print_info "创建build目录..."
    mkdir -p "$ZMAP_MULTI_BUILD"
    cd "$ZMAP_MULTI_BUILD"
    
    print_info "运行cmake..."
    cmake ..
    
    print_info "编译中（这可能需要几分钟）..."
    make -j$(nproc)
    
    cd - > /dev/null
    
    if [ -f "$ZMAP_MULTI_BIN" ]; then
        print_info "ZMap (multiple_probes) 编译成功!"
    else
        print_error "ZMap (multiple_probes) 编译失败!"
        exit 1
    fi
fi

print_info ""
print_info "4. 安装Python依赖..."
pip3 install -r requirements.txt

print_info ""
print_info "5. 创建必要目录..."
mkdir -p servers static templates attack_resources/shared/ip_lists/manual attack_resources/shared/ip_lists/auto/ipdeny attack_resources/shared/ip_lists/auto/shodan attack_resources/shared/ip_lists/auto/fofa

print_info ""
print_info "6. 验证安装..."
print_info "------------------------"

if [ -f "$ZMAP_SINGLE_BIN" ]; then
    print_info "✓ ZMap (single_probe): $ZMAP_SINGLE_BIN"
else
    print_error "✗ ZMap (single_probe) 未找到"
fi

if [ -f "$ZMAP_MULTI_BIN" ]; then
    print_info "✓ ZMap (multiple_probes): $ZMAP_MULTI_BIN"
else
    print_error "✗ ZMap (multiple_probes) 未找到"
fi

python3 --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
    PY_VER=$(python3 --version 2>&1 | cut -d' ' -f2)
    print_info "✓ Python3: $PY_VER"
else
    print_error "✗ Python3 未安装"
fi

print_info "------------------------"
print_info ""
print_info "${GREEN}环境初始化完成!${NC}"
print_info ""
print_info "启动命令:"
print_info "  sudo ./start.sh"
print_info ""
print_info "访问地址:"
print_info "  http://localhost:5000"