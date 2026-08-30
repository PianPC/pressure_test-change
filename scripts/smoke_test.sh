#!/usr/bin/env bash
# 部署冒烟测试（只读 API 检查，不发起任何攻击流量）
#
# 用法: ./scripts/smoke_test.sh [BASE_URL]
#   BASE_URL 默认 http://127.0.0.1:5000，例如 ./scripts/smoke_test.sh http://127.0.0.1:8000
#
# 检查分三层：
#   FAIL —— API 不可达 / 非 200 / success 不为 true（服务层故障）
#   WARN —— API 正常但返回数据为空（可能是上游依赖故障的隐性传播，
#           例如扫描模块损坏导致资源池为空；新部署空池也会触发 WARN）
#   SKIP —— 动态端点（需 run_id）在无历史运行记录时跳过
#
# 每项检查相互独立（各自发 curl），单项失败不影响其他项的判断。
# 兼容 Flask debug 模式（"success": true）与生产模式（"success":true）两种 JSON 输出。
# 退出码: 0=全部通过(可有 WARN/SKIP), 1=存在 FAIL
set -u
BASE="${1:-http://127.0.0.1:5000}"
PASS=0; FAIL=0; WARN=0; SKIP=0
SUCCESS_RE='"success": ?true'

fetch() {
    # $1=路径 $2=HTTP方法(GET) —— 输出 "http_code\nbody"
    curl -sf --max-time 10 -X "${2:-GET}" -H 'Content-Type: application/json' \
        ${3:+-d "$3"} -w '\n%{http_code}' "$BASE$1" 2>/dev/null
}

check() {
    # check <名称> <路径> [非空断言关键词] [HTTP方法] [POST body]
    local name="$1" path="$2" nonempty_kw="${3:-}" http_m="${4:-}" post_body="${5:-}"
    local body code payload
    body=$(fetch "$path" "${http_m:-GET}" "$post_body")
    code=$(echo "$body" | tail -n1)
    payload=$(echo "$body" | sed '$d')
    if [ "$code" != "200" ] || ! echo "$payload" | grep -qE "$SUCCESS_RE"; then
        echo "  FAIL $name  (${http_m:-GET} $path)  http=$code"
        echo "       响应片段: $(echo "$payload" | head -c 200)"
        FAIL=$((FAIL+1))
        return 1
    fi
    if [ -n "$nonempty_kw" ] && ! echo "$payload" | grep -q "$nonempty_kw"; then
        echo "  WARN $name  (${http_m:-GET} $path) —— API 正常但数据为空，可能是上游依赖故障或新部署空池"
        WARN=$((WARN+1))
        return 2
    fi
    echo "  OK   $name  (${http_m:-GET} $path)"
    PASS=$((PASS+1))
}

check_raw() {
    # check_raw <名称> <路径> —— 仅断言 HTTP 200（用于无 success 字段的端点：
    # 首页 HTML、/api/config 纯状态对象、/api/servers/<m> 的 total/servers 结构）
    local name="$1" path="$2" body code
    body=$(fetch "$path")
    code=$(echo "$body" | tail -n1)
    if [ "$code" != "200" ]; then
        echo "  FAIL $name  (GET $path)  http=$code"
        FAIL=$((FAIL+1))
        return 1
    fi
    echo "  OK   $name  (GET $path)"
    PASS=$((PASS+1))
}

# 条件式深测：从 /runs 列表取第一个 run_id，无历史运行则 SKIP
first_run_id() {
    fetch "$1" | sed '$d' | grep -oE '"run_id": ?"[^"]+"' | head -1 \
        | sed 's/.*"run_id": *"\([^"]*\)".*/\1/'
}

check_dynamic() {
    # check_dynamic <名称> <路径模板，%s=run_id> [非空断言关键词]
    local name="$1" path_tpl="$2" nonempty_kw="${3:-}" runs_path="$4" rid
    rid=$(first_run_id "$runs_path")
    if [ -z "$rid" ]; then
        echo "  SKIP $name —— 无历史运行记录"
        SKIP=$((SKIP+1))
        return
    fi
    check "$name (run=$rid)" "$(printf "$path_tpl" "$rid")" "$nonempty_kw"
}

echo "== 部署冒烟测试: $BASE =="

echo "[1] 基础服务"
check_raw "首页"     "/"
check     "系统信息" "/api/system/info"
check_raw "前端配置" "/api/config"

echo "[2] 服务器 IP 管理"
for m in tcp dns memcached ntp; do
    check_raw "servers/$m 概览"    "/api/servers/$m"
    check     "servers/$m 文件列表" "/api/servers/$m/files" '"full_path"'
    check "servers/$m IP 明细"  "/api/servers/$m/list"
    check "servers/$m 地理分布" "/api/servers/$m/geo"
    check "servers/$m 数量统计" "/api/servers/count" "" "POST" "{\"protocols\":[\"$m\"]}"
done

echo "[3] 共享资源池 API"
check "共享池资源"      "/api/attack-resource/resources"
check "资源来源列表"    "/api/attack-resource/resources/sources"
check "可用国家列表"    "/api/attack-resource/resources/countries"
check "抓取凭证列表"    "/api/attack-resource/credentials"
for p in tcp dns memcached ntp; do
    check "attack-resource/$p 资源"  "/api/attack-resource/$p/resources" '"full_path"'
    check "attack-resource/$p 运行"  "/api/attack-resource/$p/runs"
done

echo "[4] 协议扫描模块"
check "tcp-scan 资源列表"  "/api/tcp-scan/resources"
check "tcp-scan 预检"      "/api/tcp-scan/preflight"
check "tcp-scan 运行列表"  "/api/tcp-scan/runs"
check "tcp-scan 状态"      "/api/tcp-scan/state"
for p in dns memcached ntp; do
    check "$p-scan 资源列表" "/api/$p-scan/resources" '"full_path"'
    check "$p-scan 运行列表" "/api/$p-scan/runs"
    check "$p-scan 状态"     "/api/$p-scan/state"
done
check "dns 查询类型"       "/api/dns-scan/query-types"
check "memcached 命令类型" "/api/memcached-scan/cmd-types"
check "ntp 探测动作"       "/api/ntp-scan/probe-actions"

echo "[5] 动态端点深测（依赖 /runs 结果，无历史运行自动跳过）"
for p in tcp dns memcached ntp; do
    check_dynamic "$p-scan 运行详情" "/api/$p-scan/runs/%s" "" "/api/$p-scan/runs"
    check_dynamic "$p-scan 运行日志" "/api/$p-scan/runs/%s/logs" "" "/api/$p-scan/runs"
done
for p in dns memcached ntp; do
    check_dynamic "$p-scan 扫描结果" "/api/$p-scan/runs/%s/results" "" "/api/$p-scan/runs"
done

echo "== 结果: $PASS 通过, $WARN 警告, $SKIP 跳过, $FAIL 失败 =="

if [ $FAIL -gt 0 ]; then
    echo "--- 诊断提示 ---"
    echo "  [1] 组失败        → Flask 未启动 / 端口不对 / 崩溃，查服务日志"
    echo "  [2] 组失败        → pressure 路由异常：目录缺失、ip_resource_catalog 导入失败"
    echo "      geo 失败      → GEOIP 链路异常（mmdb 路径/缓存，历史高频故障点）"
    echo "      count 失败    → IP 统计链路异常（文件读取/解析）"
    echo "  [3] 组失败        → 攻击资源模块异常：目录缺失、qualified_pool 导入失败"
    echo "  [4] 组失败        → 扫描蓝图异常：协议 scanner 模块导入失败；"
    echo "      preflight 失败 → zmap 二进制缺失或未编译（build_zmap.sh）"
    echo "  [5] 组失败        → 运行记录读写异常（详情/日志/结果文件）"
    echo "  多组同时失败      → 优先查服务启动时的 Traceback（日志开头）"
    exit 1
fi
echo "后端 API 层健康。请再用浏览器做 5 分钟前端点验（脚本测不到 UI 交互）。"
[ $WARN -gt 0 ] && echo "存在 WARN 项：若为存量部署，建议按第 3 步流程确认对应数据链路。" || true
