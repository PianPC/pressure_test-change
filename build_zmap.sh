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
print_info "     ZMap 编译 (single + multi)"
print_info "========================================"

# ---------- 路径定义 ----------
ZMAP_SINGLE="vendor/weaponizing-censors/zmap"
ZMAP_MULTI="vendor/weaponizing-censors/zmap_multiple_probes"
ZMAP_SINGLE_BUILD="${ZMAP_SINGLE}/build"
ZMAP_MULTI_BUILD="${ZMAP_MULTI}/build"
ZMAP_SINGLE_BIN="${ZMAP_SINGLE_BUILD}/src/zmap"
ZMAP_MULTI_BIN="${ZMAP_MULTI_BUILD}/src/zmap"

# ---------- 安装依赖 ----------
install_deps() {
    print_info "检查并安装编译依赖..."
    sudo apt update -qq
    sudo apt install -y build-essential cmake \
        libjson-c-dev libpcap-dev libgmp-dev \
        gengetopt flex byacc pkg-config \
        libunistring-dev
}

# ---------- 修复源码兼容性问题 ----------
fix_source() {
    local dir=$1
    local name=$2

    print_info "修复 $name 源码兼容性..."

    # 1. 修复硬编码的绝对路径 #include（原开发者机器残留）
    local fixed=0
    for f in "$dir"/src/*opt.c "$dir"/src/*opt_compat.c; do
        [ -f "$f" ] || continue
        if grep -q '#include "/home/weaponizing-censors' "$f"; then
            sed -i 's|#include "/home/weaponizing-censors/[^"]*/src/\([^"]*\)"|#include "\1"|' "$f"
            fixed=$((fixed + 1))
        fi
    done
    if [ "$fixed" -gt 0 ]; then
        print_info "  已修复 $fixed 个文件的硬编码 #include 路径"
    fi

    # 2. 修复 state.c 中 source_ip_addresses = NULL（GCC 15 严格检查）
    local state_file="$dir/src/state.c"
    if [ -f "$state_file" ] && grep -q 'source_ip_addresses = NULL' "$state_file"; then
        sed -i 's/source_ip_addresses = NULL/source_ip_addresses = {0}/' "$state_file"
        print_info "  已修复 state.c 的空指针初始化问题"
    fi

    # 3. 清理旧构建产物中的硬编码路径
    if [ -d "$dir/src/CMakeFiles" ]; then
        rm -rf "$dir/src/CMakeFiles"
        print_info "  已清理旧的 CMakeFiles 缓存"
    fi
}

# ---------- 修复 json-c 问题 ----------
fix_json_c() {
    local cmake_file="$1"
    if [ ! -f "$cmake_file" ]; then
        print_warn "文件不存在: $cmake_file"
        return 1
    fi

    # 如果已经修复过，就跳过
    if grep -q 'string(REPLACE ";" " " JSON_C_CFLAGS' "$cmake_file"; then
        print_info "CMakeLists.txt 已修复，跳过"
        return 0
    fi

    print_info "修复 json-c 兼容性: $cmake_file"

    # 插入修复代码（处理分号列表问题）
    sed -i '/pkg_check_modules.*JSON.*json-c/a\    string(REPLACE ";" " " JSON_C_CFLAGS "${JSON_C_CFLAGS}")' "$cmake_file"

    # 确保 include_directories 存在
    if ! grep -q 'include_directories.*JSON' "$cmake_file"; then
        sed -i '/pkg_check_modules.*JSON.*json-c/a\    include_directories(${JSON_C_INCLUDE_DIRS})' "$cmake_file"
    fi
}

# ---------- 主编译函数 ----------
build_zmap() {
    local dir=$1
    local name=$2
    local build_dir="${dir}/build"
    local bin_path="${build_dir}/src/zmap"

    if [ -f "$bin_path" ]; then
        print_info "$name 已编译，跳过..."
        return 0
    fi

    print_info "正在编译 $name ..."

    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"

    print_info "运行 cmake ..."
    cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
          -DCMAKE_BUILD_TYPE=Release ..

    print_info "正在编译（可能需要 1-3 分钟）..."
    make -j$(nproc)

    cd - > /dev/null

    if [ -f "$bin_path" ]; then
        print_info "${GREEN}$name 编译成功！${NC}"
    else
        print_error "$name 编译失败！"
        exit 1
    fi
}

# ====================== 执行流程 ======================

install_deps

# 修复两个项目的 CMakeLists.txt
fix_json_c "${ZMAP_SINGLE}/CMakeLists.txt"
fix_json_c "${ZMAP_MULTI}/CMakeLists.txt"

# 修复源码并编译 single probe
fix_source "$ZMAP_SINGLE" "ZMap (single_probe)"
build_zmap "$ZMAP_SINGLE" "ZMap (single_probe)"

# 修复源码并编译 multiple probes
fix_source "$ZMAP_MULTI" "ZMap (multiple_probes)"
build_zmap "$ZMAP_MULTI" "ZMap (multiple_probes)"

print_info ""
print_info "${GREEN}所有编译完成！${NC}"
print_info "可执行文件位置："
print_info "   Single  : ${ZMAP_SINGLE_BIN}"
print_info "   Multiple: ${ZMAP_MULTI_BIN}"

echo ""
print_info "使用示例："
echo "   sudo ${ZMAP_SINGLE_BIN} -h"
echo "   sudo ${ZMAP_MULTI_BIN} -h"
