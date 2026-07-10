#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_info "========================================"
print_info "      仅编译 ZMap（single + multi）"
print_info "========================================"
print_info ""

# 如果非 root，给出提醒（编译 ZMap 通常需要 root 权限，因为安装 libpcap 开发包等）
if [ "$EUID" -ne 0 ]; then
    print_warn "建议使用 root 权限运行，否则可能因缺少依赖而编译失败。"
    print_info "若已手动安装依赖，可忽略。"
fi

# ---------- 编译 single_probe ----------
print_info "编译 ZMap (single_probe)..."
ZMAP_SINGLE="vendor/weaponizing-censors/zmap"
ZMAP_SINGLE_BUILD="${ZMAP_SINGLE}/build"
ZMAP_SINGLE_BIN="${ZMAP_SINGLE_BUILD}/src/zmap"

if [ -f "$ZMAP_SINGLE_BIN" ]; then
    print_info "ZMap (single_probe) 已编译，跳过..."
else
    print_info "创建 build 目录..."
    mkdir -p "$ZMAP_SINGLE_BUILD"
    cd "$ZMAP_SINGLE_BUILD"
    print_info "运行 cmake ..."
    cmake ..
    print_info "编译中（可能需要几分钟）..."
    make -j$(nproc)
    cd - > /dev/null
    if [ -f "$ZMAP_SINGLE_BIN" ]; then
        print_info "ZMap (single_probe) 编译成功!"
    else
        print_error "编译失败！"
        exit 1
    fi
fi

# ---------- 编译 multiple_probes ----------
print_info "编译 ZMap (multiple_probes)..."
ZMAP_MULTI="vendor/weaponizing-censors/zmap_multiple_probes"
ZMAP_MULTI_BUILD="${ZMAP_MULTI}/build"
ZMAP_MULTI_BIN="${ZMAP_MULTI_BUILD}/src/zmap"

if [ -f "$ZMAP_MULTI_BIN" ]; then
    print_info "ZMap (multiple_probes) 已编译，跳过..."
else
    print_info "创建 build 目录..."
    mkdir -p "$ZMAP_MULTI_BUILD"
    cd "$ZMAP_MULTI_BUILD"
    print_info "运行 cmake ..."
    cmake ..
    print_info "编译中（可能需要几分钟）..."
    make -j$(nproc)
    cd - > /dev/null
    if [ -f "$ZMAP_MULTI_BIN" ]; then
        print_info "ZMap (multiple_probes) 编译成功!"
    else
        print_error "编译失败！"
        exit 1
    fi
fi

print_info ""
print_info "${GREEN}ZMap 编译完成！${NC}"
print_info "可执行文件位置："
print_info "  single  : $ZMAP_SINGLE_BIN"
print_info "  multiple: $ZMAP_MULTI_BIN"
