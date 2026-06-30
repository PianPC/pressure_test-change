#!/bin/bash
# limit_port80_ingress_police.sh
# 说明：使用 ifb + tc police 对目的端口 80 的入站流量做严格带宽上限（超出立即丢弃）
# 用法:
#   sudo ./limit_port80_ingress_police.sh start
#   sudo ./limit_port80_ingress_police.sh status
#   sudo ./limit_port80_ingress_police.sh stop

set -e

IFACE="eth0"          # 修改为你的公网网卡名（用 `ip a` 查看）
IFB_DEV="ifb0"
LIMIT_RATE="50kbit"    # 模拟受害服务器的带宽上限（例如 1mbit）
BURST_BYTES="1600"    # police 的突发允许（bytes），设小以尽量减少突发
PORT="8080"

require_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "[!] 请以 root 权限运行（sudo）"
    exit 1
  fi
}

load_ifb() {
  echo "[+] 加载 ifb 模块并启用 ${IFB_DEV} ..."
  modprobe ifb || true
  ip link set dev ${IFB_DEV} up || ( ip link add ${IFB_DEV} type ifb >/dev/null 2>&1 && ip link set dev ${IFB_DEV} up )
}

start_limit() {
  echo "[+] 启动 ingress police 限速（port ${PORT}）: rate=${LIMIT_RATE} burst=${BURST_BYTES}B (超出直接丢弃)"
  load_ifb

  # 清理旧规则（安全）
  tc qdisc del dev ${IFACE} ingress 2>/dev/null || true
  tc qdisc del dev ${IFB_DEV} root 2>/dev/null || true

  # 1) 在物理接口上添加 ingress qdisc 并重定向到 ifb
  echo "[>] 配置 ingress 重定向: ${IFACE} -> ${IFB_DEV}"
  tc qdisc add dev ${IFACE} handle ffff: ingress
  tc filter add dev ${IFACE} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ${IFB_DEV}

  # 2) 在 ifb 上添加根 qdisc（需要一个占位）
  tc qdisc add dev ${IFB_DEV} root handle 1: prio

  # 3) 添加 filter + police：对 dport 80 的 UDP 和 TCP 包，设置 police rate 丢弃超出部分
  echo "[>] 添加 police 过滤器：UDP -> dport ${PORT}"
  tc filter add dev ${IFB_DEV} protocol ip parent 1: prio 1 u32 \
    match ip dport ${PORT} 0xffff match ip protocol 17 0xff \
    action police rate ${LIMIT_RATE} burst ${BURST_BYTES} drop flowid :1

  echo "[>] 添加 police 过滤器：TCP -> dport ${PORT}"
  tc filter add dev ${IFB_DEV} protocol ip parent 1: prio 2 u32 \
    match ip dport ${PORT} 0xffff match ip protocol 6 0xff \
    action police rate ${LIMIT_RATE} burst ${BURST_BYTES} drop flowid :1

  echo "[✅] 已生效：入站到端口 ${PORT} 的流量在 ${IFB_DEV} 被 police 为 ${LIMIT_RATE}（超出立即丢弃）。"
  echo "提示: 若要查看统计请运行: sudo $0 status"
  echo "注意：请确保 SSH 管理端口/管理 IP 不受影响（本脚本仅匹配 dport ${PORT}）"
}

show_status() {
  echo "===== ${IFACE} ingress qdisc ====="
  tc -s qdisc show dev ${IFACE} || true
  echo
  echo "===== ${IFB_DEV} qdisc/classes/filters ====="
  tc -s qdisc show dev ${IFB_DEV} || true
  echo
  echo "===== tc filter show (ifb0) ====="
  tc filter show dev ${IFB_DEV} || true
  echo
  echo "检查被 police 丢弃的统计（如果有）请注意 tc -s 输出中的 dropped/overlimits"
  echo
  echo "提示：抓包查看入站（在 ifb0）:"
  echo "  sudo tcpdump -i ${IFB_DEV} 'udp port ${PORT} or tcp port ${PORT}' -n -vv"
  echo
  echo "若需手工撤销，请运行: sudo $0 stop"
}

stop_limit() {
  echo "[+] 清除所有相关规则（恢复之前的状态）..."
  tc qdisc del dev ${IFACE} ingress 2>/dev/null || true
  tc qdisc del dev ${IFB_DEV} root 2>/dev/null || true
  echo "[✅] 已清除 tc 规则。"
}

case "$1" in
  start)
    require_root
    start_limit
    ;;
  stop)
    require_root
    stop_limit
    ;;
  status)
    show_status
    ;;
  *)
    echo "用法: $0 {start|stop|status}"
    exit 1
    ;;
esac
