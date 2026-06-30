#!/usr/bin/env python3
import socket
import struct
import time
import threading

# 输入文件（你现在的列表）
INPUT_FILE = "ip_12_17_1.txt"
# 输出文件（清洗后的高倍率列表）
OUTPUT_FILE = "niceip_12_17_1.txt"
# 阈值：版本1: 只有回包大于 1000 字节的才保留 
SIZE_THRESHOLD = 1500

print(f"🚀 开始清洗 DNS 列表，保留回包 > {SIZE_THRESHOLD}B 的服务器...")

valid_ips = []
lock = threading.Lock()

def check_server(ip):
    try:
        # 构造一个标准的 ripe.net TXT 查询 (带 DNSSEC)
        query_id = struct.pack('!H', 0x1234)
        # 头部: ID, Flags(Recursion Desired), Questions=1
        header = query_id + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
        # Query: ripe.net IN TXT
        qname = b'\x04ripe\x03net\x00'
        qtype = b'\x00\x10' # TXT
        qclass = b'\x00\x01'
        # EDNS0: Buffer 4096, DNSSEC OK
        additional = b'\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00'
        
        message = header + qname + qtype + qclass + additional
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0) # 2秒超时
        start = time.time()
        sock.sendto(message, (ip, 53))
        data, _ = sock.recvfrom(65535)
        end = time.time()
        sock.close()
        
        size = len(data)
        if size > SIZE_THRESHOLD:
            with lock:
                valid_ips.append(ip)
                # 实时写入，防止脚本中断
                with open(OUTPUT_FILE, "a") as f:
                    f.write(f"{ip}\n")
            print(f"[✅ 保留] {ip} | 回包: \033[1;32m{size} Bytes\033[0m | 耗时: {(end-start)*1000:.0f}ms")
        else:
            # print(f"[❌ 剔除] {ip} | 回包太小: {size} Bytes")
            pass
            
    except Exception:
        # print(f"[❌ 失败] {ip} | 超时或不可达")
        pass

# 多线程运行
ips = []
try:
    with open(INPUT_FILE, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
except:
    print(f"找不到 {INPUT_FILE}")
    exit()

threads = []
for ip in ips:
    # 控制并发数，避免把自己网卡打爆
    while len(threading.enumerate()) > 100:
        time.sleep(0.1)
    t = threading.Thread(target=check_server, args=(ip,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print(f"\n🎉 清洗完成！")
print(f"原始 IP 数: {len(ips)}")
print(f"优质 IP 数: {len(valid_ips)}")
print(f"请将 {OUTPUT_FILE} 重命名为 niceip.txt 并重新运行攻击脚本。")