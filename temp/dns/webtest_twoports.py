#!/usr/bin/env python3
import os
import time
import socket
import struct
from random import choice, randint, shuffle
import psutil
import signal
import sys
import threading
from threading import Lock
from datetime import datetime, timedelta
import select

# ========= 配置参数 =========
DURATION_MINUTES = 30           # 总持续时间（分钟）
DNS_QUERY_TYPE = 'TXT'
USE_DNSSEC = True
BASE_DEST_PORT = 8080          # 基础端口
DNS_IP_LIST_FILE = "niceip.txt"
QUERY_NAME = "ripe.net"
TARGET_PPS = 3000              # 降低发送速率到3000 pps
THREAD_COUNT = 6               # 减少线程数
EXPECTED_AMPLIFICATION = 20    # 预期放大倍数
RECV_PORTS = [8080, 80]        # 多端口接收：8080和80端口

# ========= DNS 类型映射 =========
dns_type_map = {
    "TXT": 16, "ANY": 255, "DNSKEY": 48, "RRSIG": 46
}
query_type_val = dns_type_map.get(DNS_QUERY_TYPE.upper(), 16)

# ========= 全局统计 =========
total_packets_sent = 0
total_bytes_sent = 0
total_packets_received = 0
total_bytes_received = 0
start_time = time.time()
end_time = start_time + (DURATION_MINUTES * 60)
is_running = True
stats_lock = Lock()

# 速率统计变量
send_rate_history = []  # 存储发送速率历史 [(timestamp, pps, mbps)]
recv_rate_history = []  # 存储接收速率历史 [(timestamp, pps, mbps)]
max_history_points = 300  # 保留最近300个数据点

# 端口轮询索引
current_port_index = 0

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
    print(f"✅ 已加载 {len(dns_servers)} 个DNS服务器")
except FileNotFoundError:
    print(f"[❌] 找不到 {DNS_IP_LIST_FILE}")
    exit(1)

if not dns_servers:
    print("[❌] DNS IP 列表为空")
    exit(1)

print(f"\n🎯 开始优化压力测试")
print(f"⏰ 持续时间: {DURATION_MINUTES} 分钟")
print(f"🚀 目标速率: {TARGET_PPS} pps")
print(f"🧵 并发线程: {THREAD_COUNT}")
print(f"🔢 接收端口: {RECV_PORTS}")
print(f"📡 DNS服务器数: {len(dns_servers)}")
print(f"💥 预期放大倍数: {EXPECTED_AMPLIFICATION}x")

# ========= 预计算原始数据包 =========
print("\n📦 预计算数据包模板...")

# 获取本机IP
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    src_ip = s.getsockname()[0]
    s.close()
    print(f"📡 源IP地址: {src_ip}")
except:
    src_ip = "127.0.0.1"
    print("⚠️  使用默认源IP: 127.0.0.1")

# DNS查询数据（固定部分）
flags = 0x8000 if USE_DNSSEC else 0x0000

def get_next_source_port():
    """轮询获取下一个源端口"""
    global current_port_index
    port = RECV_PORTS[current_port_index]
    current_port_index = (current_port_index + 1) % len(RECV_PORTS)
    return port

# 构建DNS查询的原始字节
def build_dns_query():
    # DNS头部
    transaction_id = randint(0, 65535)
    flags = 0x0100  # 标准查询
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 1 if USE_DNSSEC else 0
    
    dns_header = struct.pack('!HHHHHH', 
                           transaction_id, flags, questions, 
                           answer_rrs, authority_rrs, additional_rrs)
    
    # DNS查询部分
    qname_parts = QUERY_NAME.split('.')
    qname = b''
    for part in qname_parts:
        qname += struct.pack('B', len(part)) + part.encode()
    qname += b'\x00'  # 结束
    
    qtype = struct.pack('!H', query_type_val)
    qclass = struct.pack('!H', 1)  # IN class
    
    dns_query = qname + qtype + qclass
    
    # OPT记录（用于DNSSEC）
    if USE_DNSSEC:
        opt_name = b'\x00'  # 根域名
        opt_type = struct.pack('!H', 41)  # OPT
        udp_payload_size = struct.pack('!H', 4096)  # 扩展UDP大小
        extended_rcode = 0
        edns_version = 0
        z = 0x8000  # DNSSEC OK flag
        opt_rdlen = struct.pack('!H', 0)  # 空RDATA
        
        opt_record = (opt_name + opt_type + udp_payload_size + 
                     struct.pack('!B', extended_rcode) + 
                     struct.pack('!B', edns_version) + 
                     struct.pack('!H', z) + opt_rdlen)
        
        return dns_header + dns_query + opt_record
    else:
        return dns_header + dns_query

dns_query_data = build_dns_query()

# ========= 构建原始IP/UDP数据包 =========
def build_raw_packet(dst_ip, src_port):
    # IP头部
    ip_ver_ihl = 0x45  # IPv4, 头部长度5*4=20字节
    ip_tos = 0
    ip_total_len = 20 + 8 + len(dns_query_data)  # IP + UDP + DNS
    ip_id = randint(0, 65535)
    ip_flags_frag = 0x4000  # Don't fragment
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0  # 计算校验和太耗时，设为0
    
    # 转换IP地址为字节
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
                          ip_ver_ihl, ip_tos, ip_total_len,
                          ip_id, ip_flags_frag, ip_ttl, ip_proto,
                          ip_check, src_ip_bytes, dst_ip_bytes)
    
    # UDP头部 - 使用指定的源端口
    udp_src = src_port
    udp_dst = 53
    udp_len = 8 + len(dns_query_data)
    udp_check = 0  # UDP校验和可选
    
    udp_header = struct.pack('!HHHH', udp_src, udp_dst, udp_len, udp_check)
    
    return ip_header + udp_header + dns_query_data

# ========= 速率统计函数 =========
def update_rate_stats(send_pps, send_mbps, recv_pps, recv_mbps):
    """更新速率统计历史"""
    global send_rate_history, recv_rate_history
    current_time = time.time()
    
    with stats_lock:
        send_rate_history.append((current_time, send_pps, send_mbps))
        recv_rate_history.append((current_time, recv_pps, recv_mbps))
        
        # 保持历史数据不超过最大点数
        if len(send_rate_history) > max_history_points:
            send_rate_history.pop(0)
        if len(recv_rate_history) > max_history_points:
            recv_rate_history.pop(0)

def get_rate_stats():
    """获取速率统计信息"""
    if not send_rate_history or not recv_rate_history:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    
    with stats_lock:
        # 发送速率统计
        send_recent = send_rate_history[-10:] if len(send_rate_history) >= 10 else send_rate_history
        if send_recent:
            send_current_pps = send_recent[-1][1]
            send_current_mbps = send_recent[-1][2]
            send_avg_pps = sum(pps for _, pps, _ in send_recent) / len(send_recent)
            send_avg_mbps = sum(mbps for _, _, mbps in send_recent) / len(send_recent)
            send_max_pps = max(pps for _, pps, _ in send_recent)
            send_max_mbps = max(mbps for _, _, mbps in send_recent)
        else:
            send_current_pps, send_current_mbps, send_avg_pps, send_avg_mbps, send_max_pps, send_max_mbps = 0, 0, 0, 0, 0, 0
        
        # 接收速率统计
        recv_recent = recv_rate_history[-10:] if len(recv_rate_history) >= 10 else recv_rate_history
        if recv_recent:
            recv_current_pps = recv_recent[-1][1]
            recv_current_mbps = recv_recent[-1][2]
            recv_avg_pps = sum(pps for _, pps, _ in recv_recent) / len(recv_recent)
            recv_avg_mbps = sum(mbps for _, _, mbps in recv_recent) / len(recv_recent)
            recv_max_pps = max(pps for _, pps, _ in recv_recent)
            recv_max_mbps = max(mbps for _, _, mbps in recv_recent)
        else:
            recv_current_pps, recv_current_mbps, recv_avg_pps, recv_avg_mbps, recv_max_pps, recv_max_mbps = 0, 0, 0, 0, 0, 0
        
        return (send_current_pps, send_current_mbps, send_avg_pps, send_avg_mbps, send_max_pps, send_max_mbps,
                recv_current_pps, recv_current_mbps, recv_avg_pps, recv_avg_mbps, recv_max_pps, recv_max_mbps)

def print_rate_dashboard():
    """打印速率仪表板"""
    (send_current_pps, send_current_mbps, send_avg_pps, send_avg_mbps, send_max_pps, send_max_mbps,
     recv_current_pps, recv_current_mbps, recv_avg_pps, recv_avg_mbps, recv_max_pps, recv_max_mbps) = get_rate_stats()
    
    # 计算放大倍数 - 使用当前速率
    amplification_factor = recv_current_mbps / send_current_mbps if send_current_mbps > 0 else 0
    
    # 计算响应率
    response_rate = (recv_current_pps / send_current_pps * 100) if send_current_pps > 0 else 0
    
    # 计算目标达成率
    target_percentage = (send_current_pps / TARGET_PPS * 100) if TARGET_PPS > 0 else 0
    
    # 选择表情符号表示状态
    if target_percentage >= 90:
        status_emoji = "🎯"
    elif target_percentage >= 70:
        status_emoji = "⚡"
    elif target_percentage >= 50:
        status_emoji = "🚀"
    else:
        status_emoji = "🐢"
    
    # 放大倍数状态
    if amplification_factor >= EXPECTED_AMPLIFICATION * 0.9:
        amp_emoji = "💥"
    elif amplification_factor >= EXPECTED_AMPLIFICATION * 0.7:
        amp_emoji = "🔥"
    elif amplification_factor >= EXPECTED_AMPLIFICATION * 0.5:
        amp_emoji = "⚡"
    else:
        amp_emoji = "📡"
    
    # 响应率状态
    if response_rate >= 80:
        resp_emoji = "✅"
    elif response_rate >= 50:
        resp_emoji = "⚠️"
    else:
        resp_emoji = "❌"
    
    print("\n" + "="*80)
    print(f"{status_emoji} 优化版DNS压力测试监控面板 {status_emoji}")
    print("="*80)
    
    print(f"📤 发送速率: {send_current_pps:>8.0f} pps | {send_current_mbps:>6.1f} Mbps")
    print(f"📥 接收速率: {recv_current_pps:>8.0f} pps | {recv_current_mbps:>6.1f} Mbps")
    print(f"{amp_emoji} 放大倍数: {amplification_factor:>7.1f}x (预期: {EXPECTED_AMPLIFICATION}x)")
    print(f"{resp_emoji} DNS响应率: {response_rate:>6.1f}%")
    
    print("-"*80)
    print(f"📊 发送平均: {send_avg_pps:>8.0f} pps | {send_avg_mbps:>6.1f} Mbps")
    print(f"📊 接收平均: {recv_avg_pps:>8.0f} pps | {recv_avg_mbps:>6.1f} Mbps")
    
    print(f"🏆 发送峰值: {send_max_pps:>8.0f} pps | {send_max_mbps:>6.1f} Mbps")
    print(f"🏆 接收峰值: {recv_max_pps:>8.0f} pps | {recv_max_mbps:>6.1f} Mbps")
    
    print("-"*80)
    print(f"🎯 目标达成: {target_percentage:>7.1f}% ({send_current_pps:,.0f}/{TARGET_PPS:,} pps)")
    
    # 进度条显示
    bar_length = 30
    filled_length = int(bar_length * send_current_pps / TARGET_PPS) if TARGET_PPS > 0 else 0
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    print(f"📏 进度指示: [{bar}]")
    
    # 线程状态
    active_threads = threading.active_count() - 1  # 减去主线程
    print(f"🧵 活动线程: {active_threads}/{THREAD_COUNT + len(RECV_PORTS)}")
    
    # 时间信息
    elapsed = time.time() - start_time
    remaining = max(0, end_time - time.time())
    elapsed_str = str(timedelta(seconds=int(elapsed)))
    remaining_str = str(timedelta(seconds=int(remaining)))
    print(f"⏱️  已运行: {elapsed_str} | 剩余: {remaining_str}")
    
    # 内存使用
    mem_mb = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    print(f"💾 内存使用: {mem_mb:.1f} MB")
    
    # CPU使用率
    cpu_percent = psutil.cpu_percent(interval=None)
    print(f"🔢 CPU使用率: {cpu_percent:.1f}%")
    
    print("="*80)

# ========= 多端口接收线程 =========
def recv_worker(port):
    """接收DNS响应包 - 多端口版本"""
    global total_packets_received, total_bytes_received
    
    # 创建接收套接字
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 增加接收缓冲区大小
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)  # 2MB缓冲区
        recv_sock.bind(('0.0.0.0', port))
        recv_sock.settimeout(0.1)  # 设置短超时以便检查停止条件
        print(f"📡 接收线程启动，监听端口 {port}")
    except Exception as e:
        print(f"[❌] 接收线程(端口{port})错误: {e}")
        return
    
    packets_received = 0
    last_log_time = time.time()
    
    while is_running and time.time() < end_time:
        try:
            # 接收数据包
            data, addr = recv_sock.recvfrom(65535)
            
            # 简单验证：确保是DNS响应包（长度大于DNS头部）
            if len(data) >= 12:  # DNS头部至少12字节
                with stats_lock:
                    total_packets_received += 1
                    total_bytes_received += len(data)
                    packets_received += 1
            
            # 每收到100个包打印一次调试信息
            if packets_received > 0 and packets_received % 100 == 0 and time.time() - last_log_time > 2:
                print(f"📥 端口{port}接收: 已接收 {packets_received} 个响应包")
                last_log_time = time.time()
                
        except socket.timeout:
            # 超时是正常的，继续循环
            continue
        except Exception as e:
            # 打印错误但继续运行
            if time.time() - last_log_time > 5:
                print(f"[⚠️] 端口{port}接收错误: {e}")
                last_log_time = time.time()
            continue
    
    recv_sock.close()
    print(f"📥 端口{port}接收线程结束，共接收 {packets_received} 个包")

# ========= 高效发送线程 =========
def send_worker(worker_id):
    global total_packets_sent, total_bytes_sent
    
    # 创建原始套接字
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print(f"[❌] 需要root权限运行原始套接字")
        return 0, 0
    
    worker_packets = 0
    worker_bytes = 0
    
    # 计算每个线程的目标PPS
    target_pps_per_thread = TARGET_PPS // THREAD_COUNT
    if target_pps_per_thread == 0:
        target_pps_per_thread = 1
    
    print(f"🧵 工作线程 {worker_id} 启动，目标: {target_pps_per_thread} pps")
    
    # 简单批次控制
    batch_size = max(5, target_pps_per_thread // 10)  # 更小的批次大小
    
    try:
        batch_count = 0
        
        while is_running and time.time() < end_time:
            batch_packets = 0
            batch_bytes = 0
            batch_start = time.time()
            
            # 发送一个批次
            for _ in range(batch_size):
                if not is_running or time.time() >= end_time:
                    break
                
                dst_ip = choice(dns_servers)
                src_port = get_next_source_port()  # 使用轮询的源端口
                packet_data = build_raw_packet(dst_ip, src_port)
                
                try:
                    sock.sendto(packet_data, (dst_ip, 0))
                    batch_packets += 1
                    batch_bytes += len(packet_data)
                except Exception as e:
                    # 忽略发送错误，继续发送
                    pass
            
            # 更新统计
            with stats_lock:
                total_packets_sent += batch_packets
                total_bytes_sent += batch_bytes
            worker_packets += batch_packets
            worker_bytes += batch_bytes
            
            batch_count += 1
            
            # 简单的速率控制
            batch_time = time.time() - batch_start
            expected_batch_time = batch_size / target_pps_per_thread
            sleep_time = expected_batch_time - batch_time
            
            if sleep_time > 0:
                time.sleep(sleep_time)
    
    except Exception as e:
        print(f"[❌] 工作线程 {worker_id} 错误: {e}")
    finally:
        sock.close()
    
    return worker_packets, worker_bytes

# ========= 统计显示线程 =========
def stats_worker():
    last_sent_packets = 0
    last_sent_bytes = 0
    last_recv_packets = 0
    last_recv_bytes = 0
    last_time = time.time()
    
    # 清屏并显示初始信息
    os.system('clear' if os.name == 'posix' else 'cls')
    print("🚀 优化版DNS压力测试启动中...")
    
    while is_running and time.time() < end_time:
        time.sleep(2)  # 每2秒更新一次统计
        
        current_time = time.time()
        
        # 获取当前统计值
        with stats_lock:
            current_sent_packets = total_packets_sent
            current_sent_bytes = total_bytes_sent
            current_recv_packets = total_packets_received
            current_recv_bytes = total_bytes_received
        
        time_diff = current_time - last_time
        
        if time_diff > 0:
            # 计算发送速率
            sent_packet_diff = current_sent_packets - last_sent_packets
            sent_byte_diff = current_sent_bytes - last_sent_bytes
            send_pps = sent_packet_diff / time_diff
            send_mbps = (sent_byte_diff * 8 / 1e6) / time_diff
            
            # 计算接收速率
            recv_packet_diff = current_recv_packets - last_recv_packets
            recv_byte_diff = current_recv_bytes - last_recv_bytes
            recv_pps = recv_packet_diff / time_diff
            recv_mbps = (recv_byte_diff * 8 / 1e6) / time_diff
            
            # 更新速率统计
            update_rate_stats(send_pps, send_mbps, recv_pps, recv_mbps)
            
            # 显示速率仪表板
            print_rate_dashboard()
        
        last_sent_packets = current_sent_packets
        last_sent_bytes = current_sent_bytes
        last_recv_packets = current_recv_packets
        last_recv_bytes = current_recv_bytes
        last_time = current_time

# ========= 主程序 =========
print(f"\n🚀 开始优化压力测试...")

# 预热 - 构建一个示例包计算大小
sample_packet = build_raw_packet(dns_servers[0], RECV_PORTS[0])
packet_size = len(sample_packet)
print(f"📦 每个发送包大小: {packet_size} 字节")
print(f"📦 预计响应包大小: {packet_size * EXPECTED_AMPLIFICATION} 字节")
print(f"🔢 使用接收端口: {RECV_PORTS}")

# 系统性能检查
cpu_count = os.cpu_count()
print(f"💻 CPU核心数: {cpu_count}")

# 启动多端口接收线程
recv_threads = []
for port in RECV_PORTS:
    thread = threading.Thread(target=recv_worker, args=(port,), daemon=True)
    recv_threads.append(thread)
    thread.start()

print(f"✅ 启动 {len(recv_threads)} 个接收线程")

# 启动统计线程
stats_thread = threading.Thread(target=stats_worker, daemon=True)
stats_thread.start()

# 启动工作线程
threads = []
for i in range(THREAD_COUNT):
    thread = threading.Thread(target=send_worker, args=(i+1,), daemon=True)
    threads.append(thread)
    thread.start()

print(f"\n✅ 所有线程已启动，开始优化压力测试...")
print(f"💡 提示: 使用 Ctrl+C 可随时停止测试")

# 等待所有线程完成或超时
try:
    for thread in threads:
        thread.join(timeout=end_time - time.time())
except KeyboardInterrupt:
    is_running = False
    print(f"\n🛑 用户中断测试")

# 最终统计
total_duration = time.time() - start_time
send_avg_pps = total_packets_sent / total_duration if total_duration > 0 else 0
send_avg_mbps = (total_bytes_sent * 8 / 1e6) / total_duration if total_duration > 0 else 0
recv_avg_pps = total_packets_received / total_duration if total_duration > 0 else 0
recv_avg_mbps = (total_bytes_received * 8 / 1e6) / total_duration if total_duration > 0 else 0

# 计算实际放大倍数
actual_amplification = recv_avg_mbps / send_avg_mbps if send_avg_mbps > 0 else 0
response_rate = (total_packets_received / total_packets_sent * 100) if total_packets_sent > 0 else 0

# 显示最终统计
print("\n\n🎉 优化压力测试完成!")
print("="*70)
print(f"⏱️  总运行时间: {total_duration:.1f} 秒 ({total_duration/60:.1f} 分钟)")
print(f"📦 总发送包数: {total_packets_sent:,}")
print(f"📦 总接收包数: {total_packets_received:,}")
print(f"📊 总发送数据: {total_bytes_sent / (1024*1024):.2f} MB")
print(f"📊 总接收数据: {total_bytes_received / (1024*1024):.2f} MB")
print(f"📈 平均发送速率: {send_avg_pps:.1f} pps | {send_avg_mbps:.2f} Mbps")
print(f"📈 平均接收速率: {recv_avg_pps:.1f} pps | {recv_avg_mbps:.2f} Mbps")
print(f"💥 实际放大倍数: {actual_amplification:.1f}x (预期: {EXPECTED_AMPLIFICATION}x)")
print(f"📡 DNS响应率: {response_rate:.1f}%")

# 显示速率摘要
if send_rate_history and recv_rate_history:
    (send_current_pps, send_current_mbps, send_avg_pps, send_avg_mbps, send_max_pps, send_max_mbps,
     recv_current_pps, recv_current_mbps, recv_avg_pps, recv_avg_mbps, recv_max_pps, recv_max_mbps) = get_rate_stats()
    
    print(f"🏆 发送峰值: {send_max_pps:.0f} pps | {send_max_mbps:.1f} Mbps")
    print(f"🏆 接收峰值: {recv_max_pps:.0f} pps | {recv_max_mbps:.1f} Mbps")

print("="*70)