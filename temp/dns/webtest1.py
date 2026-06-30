#!/usr/bin/env python3
import os
import time
from scapy.all import *
from random import choice, randint
import psutil
import signal
import sys
import threading

# ========= 配置参数 =========
TOTAL_MB = 5                     # 每轮发送数据（MB）
DURATION_MINUTES = 30           # 总持续时间（分钟）
DNS_QUERY_TYPE = 'TXT'
USE_DNSSEC = True
DEST_PORT = 8080
DNS_IP_LIST_FILE = "niceip.txt"
QUERY_NAME = "ripe.net"
RATE_LIMIT_PPS = 5000           # 每秒包数
THREAD_COUNT = 4                # 并发线程数
BATCH_SIZE = 100                # 每批构造的包数（减少内存使用）

# ========= DNS 类型映射 =========
dns_type_map = {
    "A": 1, "AAAA": 28, "NS": 2, "CNAME": 5, "MX": 15, "PTR": 12, "SOA": 6,
    "TXT": 16, "ANY": 255, "DNSKEY": 48, "RRSIG": 46
}
query_type_val = dns_type_map.get(DNS_QUERY_TYPE.upper(), 16)

# ========= 全局统计 =========
total_packets_sent = 0
total_bytes_sent = 0
start_time = time.time()
end_time = start_time + (DURATION_MINUTES * 60)
is_running = True
stats_lock = threading.Lock()

def signal_handler(sig, frame):
    global is_running
    print(f"\n🛑 收到停止信号，正在结束...")
    is_running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

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

src_ip = get_if_addr(conf.iface)
flags = 0x8000 if USE_DNSSEC else 0x0000

print(f"\n🎯 开始优化版压力测试")
print(f"⏰ 持续时间: {DURATION_MINUTES} 分钟")
print(f"📦 每轮数据: {TOTAL_MB} MB")
print(f"🚀 发送速率: {RATE_LIMIT_PPS} pps")
print(f"🧵 并发线程: {THREAD_COUNT}")
print(f"🎯 目标端口: {DEST_PORT}")
print(f"📡 DNS服务器数: {len(dns_servers)}")
print(f"💾 批处理大小: {BATCH_SIZE} 包/批")

# ========= 优化的数据包生成器 =========
def packet_generator(total_bytes_needed):
    """生成数据包，避免一次性占用太多内存"""
    bytes_generated = 0
    base_dns = DNS(
        rd=1,
        qd=DNSQR(qname=QUERY_NAME, qtype=query_type_val),
        ar=DNSRROPT(rclass=4096, z=flags)
    )
    base_udp = UDP(sport=DEST_PORT, dport=53)
    base_ip = IP(src=src_ip, ttl=64)
    
    while bytes_generated < total_bytes_needed and is_running:
        batch = []
        batch_bytes = 0
        
        for _ in range(BATCH_SIZE):
            if bytes_generated + batch_bytes >= total_bytes_needed:
                break
                
            dst_ip = choice(dns_servers)
            ip_layer = base_ip.copy()
            ip_layer.dst = dst_ip
            
            pkt = ip_layer / base_udp / base_dns
            pkt_bytes = len(raw(pkt))
            
            batch.append(pkt)
            batch_bytes += pkt_bytes
            
            # 检查总限制
            if bytes_generated + batch_bytes >= total_bytes_needed:
                break
        
        if batch:
            bytes_generated += batch_bytes
            yield batch, batch_bytes
        
        # 定期检查内存
        if bytes_generated % (BATCH_SIZE * 100) == 0:
            mem_mb = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
            if mem_mb > 200:  # 如果内存超过200MB，暂停一下
                time.sleep(0.1)

# ========= 工作线程函数 =========
def send_worker(worker_id, total_bytes_needed):
    """工作线程：生成并发送数据包"""
    global total_packets_sent, total_bytes_sent
    
    worker_packets_sent = 0
    worker_bytes_sent = 0
    
    try:
        packets_per_second = RATE_LIMIT_PPS // THREAD_COUNT
        if packets_per_second == 0:
            packets_per_second = 1
            
        interval = 1.0 / packets_per_second
        
        # 使用生成器获取数据包批次
        packet_gen = packet_generator(total_bytes_needed)
        
        for batch, batch_bytes in packet_gen:
            if not is_running or time.time() >= end_time:
                break
                
            # 发送这个批次
            batch_start = time.time()
            packets_in_batch = len(batch)
            
            send(batch, verbose=0)
            
            # 更新统计
            with stats_lock:
                total_packets_sent += packets_in_batch
                total_bytes_sent += batch_bytes
            worker_packets_sent += packets_in_batch
            worker_bytes_sent += batch_bytes
            
            # 速率控制
            batch_time = time.time() - batch_start
            expected_time = packets_in_batch / packets_per_second
            sleep_time = expected_time - batch_time
            
            if sleep_time > 0:
                time.sleep(sleep_time)
                
    except Exception as e:
        print(f"[❌] 工作线程 {worker_id} 错误: {e}")
    
    return worker_packets_sent, worker_bytes_sent

# ========= 优化的主循环 =========
round_count = 0
print(f"\n🚀 开始优化版压力测试...")

while is_running and time.time() < end_time:
    round_count += 1
    round_start = time.time()
    
    # 计算本轮参数
    round_bytes = int(TOTAL_MB * 1024 * 1024)
    bytes_per_thread = round_bytes // THREAD_COUNT
    
    print(f"\n🔄 第 {round_count} 轮开始 - 目标: {round_bytes/1024:.1f} KB")
    
    # 启动工作线程
    threads = []
    for i in range(THREAD_COUNT):
        # 最后一个线程处理可能的多余字节
        if i == THREAD_COUNT - 1:
            thread_bytes = round_bytes - (bytes_per_thread * (THREAD_COUNT - 1))
        else:
            thread_bytes = bytes_per_thread
            
        thread = threading.Thread(
            target=send_worker,
            args=(i + 1, thread_bytes),
            daemon=True
        )
        threads.append(thread)
        thread.start()
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    
    round_time = time.time() - round_start
    
    # 实时统计
    total_duration = time.time() - start_time
    current_rate_mbps = (total_bytes_sent * 8 / 1e6) / total_duration if total_duration > 0 else 0
    current_pps = total_packets_sent / total_duration if total_duration > 0 else 0
    remaining_time = max(0, end_time - time.time())
    
    # 内存使用情况
    mem_mb = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    print(f"✅ 第 {round_count} 轮完成: {round_time:.1f}s")
    print(f"📊 实时统计: {current_pps:.0f} pps, {current_rate_mbps:.1f} Mbps")
    print(f"💾 内存使用: {mem_mb:.1f} MB")
    print(f"⏱️  剩余时间: {remaining_time/60:.1f} 分钟")
    
    # 检查是否该结束
    if time.time() >= end_time:
        break
        
    # 短暂休息，让系统恢复
    time.sleep(1)

# ========= 最终统计 =========
total_duration = time.time() - start_time
avg_rate_mbps = (total_bytes_sent * 8 / 1e6) / total_duration if total_duration > 0 else 0
avg_pps = total_packets_sent / total_duration if total_duration > 0 else 0

print(f"\n🎉 压力测试完成!")
print(f"⏱️  总运行时间: {total_duration:.1f} 秒 ({total_duration/60:.1f} 分钟)")
print(f"📦 总发送包数: {total_packets_sent:,}")
print(f"📊 总发送数据: {total_bytes_sent / (1024*1024):.2f} MB")
print(f"📈 平均速率: {avg_rate_mbps:.2f} Mbps")
print(f"🎯 平均包率: {avg_pps:.1f} pps")
print(f"🔄 总轮次: {round_count}")