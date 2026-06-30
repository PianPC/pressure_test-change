#!/usr/bin/env python3
"""
build_dns_pcap.py
-----------------
生成 DNS 查询数据包并保存为 pcap 文件（不发送）。
可用于后续在受控环境下使用 tcpreplay 重放。
"""

import os
import time
from scapy.all import *
from random import randint, choice
import psutil

# ========= 配置参数 =========
TOTAL_MB = 1                      # 要生成的总数据量
DNS_QUERY_TYPE = 'TXT'            # 查询类型
USE_DNSSEC = True                 # 是否加 DO 位
DEST_PORT = 80                    # 响应端口（仅记录）
DNS_IP_LIST_FILE = "niceip.txt"   # 目标 IP 列表文件
QUERY_NAME = "ripe.net"           # 查询域名
PCAP_OUTPUT = "dns_test.pcap"     # 输出文件名

# ========= 类型映射 =========
dns_type_map = {
    "A": 1, "AAAA": 28, "NS": 2, "CNAME": 5, "MX": 15, "PTR": 12, "SOA": 6,
    "TXT": 16, "ANY": 255, "DNSKEY": 48, "RRSIG": 46
}
query_type_val = dns_type_map.get(DNS_QUERY_TYPE.upper(), 16)

# ========= 初始化 =========
total_bytes = int(TOTAL_MB * 1024 * 1024)
sent_bytes = 0
packets = []
src_ip = get_if_addr(conf.iface)

# ========= 加载目标列表 =========
try:
    with open(DNS_IP_LIST_FILE) as f:
        dns_servers = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print(f"[❌] 找不到 {DNS_IP_LIST_FILE}")
    exit(1)

if not dns_servers:
    print("[❌] 目标列表为空")
    exit(1)

print(f"\n📦 构造 DNS 查询: {DNS_QUERY_TYPE}+{'DNSSEC' if USE_DNSSEC else 'noDNSSEC'}")
print(f"📤 将保存为 {PCAP_OUTPUT}")
flags = 0x8000 if USE_DNSSEC else 0x0000

progress_milestones = set(int(i * total_bytes / 20) for i in range(1, 21))
last_mem = -1

# ========= 构造数据包 =========
while sent_bytes < total_bytes:
    dst_ip = choice(dns_servers)
    random_qname = f"{randint(10000,99999)}.{QUERY_NAME}"
    dns_layer = DNS(
        rd=1,
        qd=DNSQR(qname=random_qname, qtype=query_type_val),
        ar=DNSRROPT(rclass=4096, z=flags)
    )
    udp_layer = UDP(sport=DEST_PORT, dport=53)
    eth_layer = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(conf.iface))
    ip_layer = IP(dst=dst_ip, src=src_ip, ttl=64)
    pkt = eth_layer / ip_layer / udp_layer / dns_layer
    pkt_len = len(raw(pkt))
    packets.append(pkt)
    sent_bytes += pkt_len

    if sent_bytes in progress_milestones:
        percent = sent_bytes / total_bytes * 100
        mem_mb = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        if int(mem_mb) != last_mem:
            print(f"📊 构造进度: {percent:.0f}% | 内存占用: {mem_mb:.1f} MB")
            last_mem = int(mem_mb)

print(f"\n✅ 构造完成：{len(packets)} 包 ≈ {sent_bytes/1024:.1f} KB")
print(f"📈 预计响应量 ≈ {TOTAL_MB * 20:.1f} MB（假设放大 x20）")

# ========= 保存为 PCAP =========
pcap_file = os.path.abspath(PCAP_OUTPUT)
wrpcap(pcap_file, packets)
print(f"\n💾 已保存至：{pcap_file}")

print("\n💡 你可以在受控网络中用以下命令重放该文件：")
print("-----------------------------------------------------------")
print(f"sudo tcpreplay --topspeed -i <你的网卡名> {PCAP_OUTPUT}")
print("-----------------------------------------------------------")
print("可配合 iftop / tcpdump / Wireshark 查看流量表现。")
