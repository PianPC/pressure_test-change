#!/usr/bin/env bash
# 部署冒烟测试（只读 API 检查，不发起任何攻击流量）
#
# 用法: ./scripts/smoke_test.sh [BASE_URL]
#   BASE_URL 默认 http://127.0.0.1:5000，例如 ./scripts/smoke_test.sh http://127.0.0.1:8000
#
# 检查分两层：
#   FAIL  —— API 不可达 / 非 200 / success 不为 true（服务层故障）
#   WARN  —— API 正常但返回数据为空（可能是上游依赖故障的隐性传播，
#            例如扫描模块损坏导致资源池为空；新部署空池也会触发 WARN）
#
# 每项检查相互独立（各自发 curl），单项失败不影响其他项的判断。
# 退出码: 0=全部通过(可有WARN), 1=存在FAIL
set -u
BASE="${1:-http://127.0.0.1:5000}"
PASS=0; FAIL=0; WARN=0

fetch() {
    # 输出 "http_code<TAB>body"
    curl -sf --max-time 10 -w '\n%{http_code}' "$BASE$1" 2>/dev/null
}

check() {
    # check <名称> <路径> [非空标志关键词]   —— 第3参数给出时做数据级断言(WARN)
    local name="$1" path="$2" nonempty_kw="${3:-}"
    local body code payload
    body=$(fetch "$path")
    code=$(echo "$body" | tail -n1)
    payload=$(echo "$body" | sed '$d')
    if [ "$code" != "200" ] || ! echo "$payload" | grep -q '"success": true'; then
        echo "  FAIL $name  ($path)  http=$code"
        echo "       响应片段: $(echo "$payload" | head -c 200)"
        FAIL=$((FAIL+1))
        return
    fi
    if [ -n "$nonempty_kw" ] && ! echo "$payload" | grep -q "$nonempty_kw"; then
        echo "  WARN $name  ($path) —— API 正常但数据为空，可能是上游依赖故障或新部署空池"
        WARN=$((WARN+1))
        return
    fi
    echo "  OK   $name  ($path)"
    PASS=$((PASS+1))
}

echo "== 部署冒烟测试: $BASE =="

echo "[1] 基础服务"
check "首页"        "/"
check "系统信息"    "/api/system/info"
check "前端配置"    "/api/config"

echo "[2] 服务器 IP 管理（重点：tcp 文件列表验证 ip_lists 去重回退）"
for m in tcp dns memcached ntp; do
    check "servers/$m 概览"  "/api/servers/$m"
    check "servers/$m 文件"  "/api/servers/$m/files" '"full_path"'
done

echo "[3] 共享资源池 API"
check "共享池资源"      "/api/attack-resource/resources"
check "资源来源列表"    "/api/attack-resource/resources/sources"
for p in tcp dns memcached ntp; do
    check "attack-resource/$p 资源" "/api/attack-resource/$p/resources" '"full_path"'
done

echo "[4] 协议扫描模块"
for p in dns memcached ntp; do
    check "$p-scan 资源"   "/api/$p-scan/resources" '"full_path"'
    check "$p-scan 运行列表" "/api/$p-scan/runs"
done
check "tcp-scan 运行列表" "/api/tcp-scan/runs"

echo "== 结果: $PASS 通过, $WARN 警告, $FAIL 失败 =="

if [ $FAIL -gt 0 ]; then
    echo "--- 诊断提示 ---"
    echo "  [1] 组失败        → Flask 未启动 / 端口不对 / 崩溃，查服务日志"
    echo "  [2][3] 组失败     → 攻击资源模块异常：目录缺失、ip_resource_catalog 导入失败"
    echo "  [4] 组失败        → 扫描蓝图异常：协议 scanner 模块导入失败（阶段3 公共工厂依赖它们）"
    echo "  多组同时失败      → 优先查最先启动时的 Traceback（服务日志开头）"
    exit 1
fi
echo "后端 API 层健康。请再用浏览器做 5 分钟前端点验（脚本测不到 UI 交互）。"
[ $WARN -gt 0 ] && echo "存在 WARN 项：若为存量部署，建议按第 3 步流程确认对应数据链路。" || true
