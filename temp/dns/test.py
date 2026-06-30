#!/usr/bin/env python3
from scapy.all import DNS, DNSQR, DNSRROPT, UDP, IP, raw
import socket
import time
import signal
import sys

# === 配置 ===
TEST_DOMAIN = "ripe.net"   # 测试目标域名
TIMEOUT = 2                # 每个目标的收包时间窗口（秒）
INPUT_FILE = "extracted_ips.txt"

# 层头部大小（字节）
IP_HEADER = 20
UDP_HEADER = 8
NET_HEADER = IP_HEADER + UDP_HEADER  # 不包含 ETH

# === Ctrl+C 安全退出 ===
interrupted = False
def signal_handler(sig, frame):
    global interrupted
    interrupted = True
    print("\n\n⚠️ 检测到中断信号，正在安全退出...")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# === 支持的查询类型 ===
type_map = {
    "1": ("A", 1), "2": ("AAAA", 28), "3": ("NS", 2), "4": ("CNAME", 5),
    "5": ("MX", 15), "6": ("PTR", 12), "7": ("SOA", 6), "8": ("TXT", 16),
    "9": ("DNSKEY", 48), "10": ("RRSIG", 46), "11": ("NSEC", 47), "12": ("NSEC3", 50),
    "13": ("DS", 43), "14": ("CAA", 257), "15": ("SRV", 33), "16": ("NAPTR", 35),
    "17": ("CERT", 37), "18": ("LOC", 29), "19": ("SSHFP", 44), "20": ("SPF", 99),
    "21": ("URI", 256), "22": ("SVCB", 64), "23": ("HTTPS", 65), "24": ("DNAME", 39),
    "25": ("ZONEMD", 63), "26": ("OPT", 41), "27": ("ANY", 255), "28": ("AXFR", 252)
}

# === 选择查询类型 ===
def select_query_type():
    print("\n📡 请选择查询类型：")
    print("=" * 90)
    print("🧩 普通查询类型 (1–28)：\n")

    keys = list(map(int, type_map.keys()))
    for i in range(0, len(keys), 4):
        part = keys[i:i+4]
        print("   ".join([f"{k:>2}. {type_map[str(k)][0]}" for k in part]))

    print("\n🔒 带 DNSSEC 查询类型 (29–56)：\n")
    for i in range(1, 29):
        print(f"  {i+28:>2}. {type_map[str(i)][0]} +DNSSEC")

    print("=" * 90)
    choice = input("请输入编号（默认 27 = ANY）: ").strip()
    base = int(choice) if choice.isdigit() and 1 <= int(choice) <= 56 else 27
    use_dnssec = base > 28
    if use_dnssec:
        base -= 28
    qtype_name, qtype_val = type_map[str(base)]
    return qtype_name, qtype_val, use_dnssec

# === 构造 DNS 请求（仅 DNS 层字节）===
def build_dns_payload(query_name, query_type_val, dnssec=False):
    flags = 0x8000 if dnssec else 0x0000
    dns_layer = DNS(rd=1,
                    qd=DNSQR(qname=query_name, qtype=query_type_val),
                    ar=DNSRROPT(rclass=4096, z=flags))
    return raw(dns_layer)

# === UDP socket 收集多个响应包 ===
def send_and_collect(ip, port, payload, src_port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('', src_port))
    except OSError as e:
        sock.close()
        raise RuntimeError(f"无法绑定本地端口 {src_port}: {e}")

    sock.settimeout(0.4)
    send_ts = time.time()
    sock.sendto(payload, (ip, port))

    deadline = time.time() + timeout
    packets = []
    first_recv_time = None

    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break
        if addr[0] != ip:
            continue
        if first_recv_time is None:
            first_recv_time = time.time()
        packets.append(data)

    sock.close()

    total_payload_bytes = sum(len(p) for p in packets)
    latency = round(first_recv_time - send_ts, 3) if first_recv_time else ""
    return packets, total_payload_bytes, latency

# === 测试单个 DNS 服务器 ===
def test_dns_server(server_ip, query_type_val, query_name, use_dnssec, src_port, query_method):
    dns_bytes = build_dns_payload(query_name, query_type_val, use_dnssec)
    req_udp_size = len(dns_bytes)
    req_ipudp_size = req_udp_size + NET_HEADER  # 只算 IP+UDP+DNS

    try:
        packets, total_resp_bytes, latency = send_and_collect(server_ip, 53, dns_bytes, src_port, timeout=TIMEOUT)
    except Exception as e:
        return {
            "IP": server_ip,
            "Query Method": query_method,
            "Responded": f"Error: {type(e).__name__}",
            "Req": req_ipudp_size,
            "Resp": "",
            "Amp": "",
            "Latency": "",
            "EachPacket": []
        }

    if not packets:
        return {
            "IP": server_ip,
            "Query Method": query_method,
            "Responded": "No response",
            "Req": req_ipudp_size,
            "Resp": 0,
            "Amp": 0,
            "Latency": "",
            "EachPacket": []
        }

    # === 计算每个响应包的 IP+UDP+DNS 层大小 ===
    each_ipudp = [len(p) + NET_HEADER for p in packets]
    total_ipudp = sum(each_ipudp)
    amp_factor = round(total_ipudp / req_ipudp_size, 2)

    return {
        "IP": server_ip,
        "Query Method": query_method,
        "Responded": "Yes",
        "Req": req_ipudp_size,
        "Resp": total_ipudp,
        "Amp": amp_factor,
        "Latency": latency,
        "EachPacket": each_ipudp
    }

# === 打印结果 ===
def print_result(result):
    amp_str = f"\033[92m{result['Amp']}\033[0m" if isinstance(result['Amp'], (int, float)) and result['Amp'] > 0 else str(result['Amp'])
    print(f"\n🛰️ 目标: {result['IP']}")
    print(f"  → 查询类型: {result['Query Method']}")
    print(f"  → 响应状态: {result['Responded']}")
    print(f"  → 请求大小 (IP+UDP+DNS): {result['Req']} B")

    if result["EachPacket"]:
        print(f"  → 响应包大小列表 (IP+UDP+DNS): {result['EachPacket']}")
        print(f"  → 响应总大小 (IP+UDP+DNS): {result['Resp']} B")
    else:
        print("  → 无响应包数据")

    print(f"  → 放大率: {amp_str}x")
    print(f"  → 首包延迟: {result['Latency']}s")

# === 主程序 ===
def main():
    port_input = input("请输入源端口（默认 12345）: ").strip()
    src_port = int(port_input) if port_input.isdigit() else 12345

    query_name = TEST_DOMAIN
    qtype_name, qtype_val, use_dnssec = select_query_type()
    query_method = f"{qtype_name}{'+DNSSEC' if use_dnssec else ''}"

    print(f"\n📥 正在读取 IP 列表: {INPUT_FILE}")
    try:
        with open(INPUT_FILE, "r") as f:
            servers = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"❌ 文件读取失败: {e}")
        return

    print(f"\n🌐 共 {len(servers)} 个 DNS 服务器，测试域名: {query_name}，源端口: {src_port}")
    print("🧪 测试进行中...\n")

    try:
        for idx, ip in enumerate(servers, 1):
            if interrupted:
                break
            print(f"[{idx}/{len(servers)}] 测试 {ip} ...")
            result = test_dns_server(ip, qtype_val, query_name, use_dnssec, src_port, query_method)
            print_result(result)

    except KeyboardInterrupt:
        print("\n\n⚠️ 手动中断，正在退出...")

    finally:
        print(f"\n✅ 测试完成")
        print(f"💡 建议监听命令：sudo tcpdump -i <interface> udp and dst port {src_port} -nn -v")

if __name__ == "__main__":
    main()
