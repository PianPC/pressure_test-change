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

install_deps() {
    print_info "Installing build dependencies..."
    sudo apt update -qq
    sudo apt install -y \
        build-essential \
        cmake \
        pkg-config \
        libjson-c-dev \
        libpcap-dev \
        libgmp-dev \
        libunistring-dev \
        gengetopt \
        flex \
        byacc
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
    rm -rf "$build_dir"
    rm -f "$dir/CMakeCache.txt"
    rm -rf "$dir/CMakeFiles"
    rm -rf "$dir/src/CMakeFiles"
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
    print_info "$label build succeeded: $bin_path"
}

require_dir "$ZMAP_SINGLE" "Single-probe ZMap source"
require_dir "$ZMAP_MULTI" "Multi-probe ZMap source"
install_deps
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
