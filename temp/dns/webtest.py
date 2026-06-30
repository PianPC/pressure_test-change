#!/usr/bin/env python3
import os
import time
from scapy.all import *
from random import choice
import psutil

# ========= 配置参数 =========
TOTAL_MB = 1                     # 总发送数据（MB）
DNS_QUERY_TYPE = 'TXT'
USE_DNSSEC = True
DEST_PORT = 8080
DNS_IP_LIST_FILE = "niceip.txt"
QUERY_NAME = "ripe.net"          # 固定查询名（不再随机化）
RATE_LIMIT_PPS = 0               # 0 表示瞬发，>0 表示每秒包数（限速）

# ========= DNS 类型映射 =========
dns_type_map = {
    "A": 1, "AAAA": 28, "NS": 2, "CNAME": 5, "MX": 15, "PTR": 12, "SOA": 6,
    "TXT": 16, "ANY": 255, "DNSKEY": 48, "RRSIG": 46
}
query_type_val = dns_type_map.get(DNS_QUERY_TYPE.upper(), 16)

# ========= 初始变量 =========
total_bytes = int(TOTAL_MB * 1024 * 1024)
sent_bytes = 0
packets = []

# 获取本机接口 IP（scapy 的 conf.iface 会选择默认接口）
src_ip = get_if_addr(conf.iface)

# ========= 加载 DNS 服务器 =========
try:
    with open(DNS_IP_LIST_FILE) as f:
        dns_servers = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print(f"[❌] 找不到 {DNS_IP_LIST_FILE}")
    exit(1)

if not dns_servers:
    print("[❌] DNS IP 列表为空")
    exit(1)

# ========= 构造 DNS 包 =========
print(f"\n📦 构造 DNS 查询: {DNS_QUERY_TYPE}+{'DNSSEC' if USE_DNSSEC else 'noDNSSEC'}")
print(f"📤 响应将打回本机 {src_ip}:{DEST_PORT}")
flags = 0x8000 if USE_DNSSEC else 0x0000

# 进度里程碑（每 5%）
progress_milestones = set(int(i * total_bytes / 20) for i in range(1, 21))
last_mem = -1

# 使用固定查询名，不再随机化
fixed_qname = QUERY_NAME

while sent_bytes < total_bytes:
    dst_ip = choice(dns_servers)

    dns_layer = DNS(
        rd=1,
        qd=DNSQR(qname=fixed_qname, qtype=query_type_val),
        ar=DNSRROPT(rclass=4096, z=flags)
    )
    udp_layer = UDP(sport=DEST_PORT, dport=53)
    ip_layer = IP(dst=dst_ip, src=src_ip, ttl=64)
    pkt = ip_layer / udp_layer / dns_layer
    pkt_len = len(raw(pkt))
    packets.append(pkt)
    sent_bytes += pkt_len

    if sent_bytes in progress_milestones:
        percent = sent_bytes / total_bytes * 100
        mem_mb = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        if int(mem_mb) != last_mem:
            print(f"📊 构造进度: {percent:.0f}% | 内存占用: {mem_mb:.1f} MB")
            last_mem = int(mem_mb)

print(f"\n✅ 构造完成：{len(packets)} 包 ≈ {sent_bytes / 1024:.1f} KB")
print(f"📈 预计放大后响应 ≈ {TOTAL_MB * 20:.1f} MB（假设放大 x20）")

# ========= 发包 =========
print("\n🚀 正在发送...\n")
t0 = time.time()
if RATE_LIMIT_PPS == 0:
    # 瞬时一次性发送所有包（注意内存/系统队列压力）
    send(packets, verbose=0)
else:
    for i, pkt in enumerate(packets):
        send(pkt, verbose=0)
        time.sleep(1.0 / RATE_LIMIT_PPS)
t1 = time.time()

# ========= 统计 =========
duration = t1 - t0
rate_mbps = (sent_bytes * 8 / 1e6) / duration if duration > 0 else 0
print(f"\n📊 实际发送: {sent_bytes / 1024:.1f} KB")
print(f"🕒 用时: {duration:.2f}s | 速率: {rate_mbps:.2f} Mbps")
print(f"[✅ 瞬发完成] 共 {len(packets)} 包，速率 {rate_mbps:.2f} Mbps")