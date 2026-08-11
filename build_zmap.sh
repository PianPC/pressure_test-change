#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ZMAP_SINGLE="$SCRIPT_DIR/vendor/weaponizing-censors/zmap"
ZMAP_MULTI="$SCRIPT_DIR/vendor/weaponizing-censors/zmap_multiple_probes"
ZMAP_SINGLE_BUILD="$ZMAP_SINGLE/build"
ZMAP_MULTI_BUILD="$ZMAP_MULTI/build"
ZMAP_SINGLE_BIN="$ZMAP_SINGLE_BUILD/src/zmap"
ZMAP_MULTI_BIN="$ZMAP_MULTI_BUILD/src/zmap"

print_info "========================================"
print_info "     ZMap build (single + multi)"
print_info "========================================"
print_info "Workspace: $SCRIPT_DIR"

require_dir() {
    local dir="$1"
    local label="$2"
    if [ ! -d "$dir" ]; then
        print_error "$label not found: $dir"
        exit 1
    fi
}

BUILD_DEPS=(
    build-essential
    cmake
    pkg-config
    libjson-c-dev
    libpcap-dev
    libgmp-dev
    libunistring-dev
    gengetopt
    flex
    byacc
)

check_deps_installed() {
    for pkg in "${BUILD_DEPS[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            return 1
        fi
    done
    return 0
}

install_deps() {
    print_info "Installing build dependencies..."
    sudo apt update -qq
    sudo apt install -y "${BUILD_DEPS[@]}"
}

ensure_deps() {
    if check_deps_installed; then
        print_info "All build dependencies already installed, skipping apt install"
    else
        install_deps
    fi
}

fix_json_c() {
    local cmake_file="$1"
    if [ ! -f "$cmake_file" ]; then
        print_error "Missing CMakeLists.txt: $cmake_file"
        exit 1
    fi

    if ! grep -q 'string(REPLACE ";" " " JSON_C_CFLAGS' "$cmake_file"; then
        python3 - "$cmake_file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
marker = 'pkg_check_modules(JSON REQUIRED json-c)'
if marker in text and 'string(REPLACE ";" " " JSON_C_CFLAGS' not in text:
    text = text.replace(marker, marker + '\n    string(REPLACE ";" " " JSON_C_CFLAGS "${JSON_C_CFLAGS}")')
if 'include_directories(${JSON_C_INCLUDE_DIRS})' not in text and marker in text:
    text = text.replace(marker, marker + '\n    include_directories(${JSON_C_INCLUDE_DIRS})')
path.write_text(text, encoding='utf-8')
PY
        print_info "Patched json-c flags in $cmake_file"
    fi
}

fix_source_tree() {
    local dir="$1"
    local label="$2"
    print_info "Applying compatibility fixes for $label"

    # 修复 *opt.c 中的错误包含路径
    find "$dir/src" -maxdepth 1 \( -name '*opt.c' -o -name '*opt_compat.c' \) -type f | while read -r file; do
        if grep -q '#include "/home/weaponizing-censors' "$file"; then
            sed -i 's|#include "/home/weaponizing-censors/[^"]*/src/\([^"]*\)"|#include "\1"|' "$file"
            print_info "  fixed include path in $(basename "$file")"
        fi
    done

    # 修复 GCC 15 初始值问题
    local state_file="$dir/src/state.c"
    if [ -f "$state_file" ] && grep -q 'source_ip_addresses = NULL' "$state_file"; then
        sed -i 's/source_ip_addresses = NULL/source_ip_addresses = {0}/' "$state_file"
        print_info "  fixed GCC 15 initializer in state.c"
    fi

    # 修复 send.c 中的指针赋值错误 (multiple_probes 特有)
    local send_file="$dir/src/send.c"
    if [ -f "$send_file" ] && grep -q '\*p = mac_buf2;' "$send_file"; then
        sed -i 's/\*p = mac_buf2;/memcpy(p, mac_buf2, 6);/' "$send_file"
        print_info "  fixed mac_buf2 assignment in send.c"
    fi
}

clean_build_cache() {
    local dir="$1"
    local build_dir="$dir/build"
    print_info "Cleaning previous build cache under $dir"

    # 检查是否有 root 所属的残留文件（之前用 sudo 编译遗留）
    local needs_sudo=false
    for target in "$build_dir" "$dir/CMakeFiles" "$dir/src/CMakeFiles"; do
        if [ -e "$target" ] && [ ! -w "$(dirname "$target")" ]; then
            needs_sudo=true
        elif [ -e "$target" ] && ! rm -rf "$target" 2>/dev/null; then
            needs_sudo=true
        fi
    done

    if [ "$needs_sudo" = true ]; then
        print_warn "Detected root-owned build artifacts (likely from a previous sudo build). Cleaning with sudo..."
        if ! sudo rm -rf "$build_dir" "$dir/CMakeFiles" "$dir/src/CMakeFiles"; then
            print_error "Failed to clean root-owned build artifacts with sudo."
            print_error "Please run this command manually, then re-run build_zmap.sh:"
            print_error "  sudo rm -rf \"$build_dir\" \"$dir/CMakeFiles\" \"$dir/src/CMakeFiles\""
            exit 1
        fi
        rm -f "$dir/CMakeCache.txt"
    else
        rm -rf "$build_dir" "$dir/CMakeFiles" "$dir/src/CMakeFiles"
        rm -f "$dir/CMakeCache.txt"
    fi
    mkdir -p "$build_dir"
}

build_one() {
    local src_dir="$1"
    local build_dir="$2"
    local bin_path="$3"
    local label="$4"

    clean_build_cache "$src_dir"
    print_info "Configuring $label"
    cmake -S "$src_dir" -B "$build_dir" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release

    print_info "Building $label"
    cmake --build "$build_dir" -- -j"$(nproc)"

    if [ ! -f "$bin_path" ]; then
        print_error "$label build finished but binary is missing: $bin_path"
        exit 1
    fi
    chmod +x "$bin_path" || true
    if [ ! -x "$bin_path" ]; then
        print_error "$label binary is not executable: $bin_path"
        exit 1
    fi
    # 同时复制到 src/zmap (in-source)，兼容 runner.py 中查找 src/zmap 的逻辑
    cp -f "$bin_path" "$src_dir/src/zmap"
    chmod +x "$src_dir/src/zmap"
    print_info "$label build succeeded: $bin_path (also copied to $src_dir/src/zmap)"
}

require_dir "$ZMAP_SINGLE" "Single-probe ZMap source"
require_dir "$ZMAP_MULTI" "Multi-probe ZMap source"
ensure_deps
fix_json_c "$ZMAP_SINGLE/CMakeLists.txt"
fix_json_c "$ZMAP_MULTI/CMakeLists.txt"
fix_source_tree "$ZMAP_SINGLE" "ZMap (single_probe)"
fix_source_tree "$ZMAP_MULTI" "ZMap (multiple_probes)"
build_one "$ZMAP_SINGLE" "$ZMAP_SINGLE_BUILD" "$ZMAP_SINGLE_BIN" "ZMap (single_probe)"
build_one "$ZMAP_MULTI" "$ZMAP_MULTI_BUILD" "$ZMAP_MULTI_BIN" "ZMap (multiple_probes)"

print_info ""
print_info "All builds completed successfully."
print_info "Single  : $ZMAP_SINGLE_BIN"
print_info "Multiple: $ZMAP_MULTI_BIN"
print_info "Usage examples:"
echo "  sudo $ZMAP_SINGLE_BIN -h"
echo "  sudo $ZMAP_MULTI_BIN -h"
