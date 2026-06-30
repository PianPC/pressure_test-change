from scapy.all import *
import time
import os
import signal
import sys

# === 配置 ===
TEST_DOMAIN = "ripe.net"   # 测试目标域名
TIMEOUT = 2
INPUT_FILE = "niceip2.txt"

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
    "1": ("A", 1),
    "2": ("AAAA", 28),
    "3": ("NS", 2),
    "4": ("CNAME", 5),
    "5": ("MX", 15),
    "6": ("PTR", 12),
    "7": ("SOA", 6),
    "8": ("TXT", 16),
    "9": ("DNSKEY", 48),
    "10": ("RRSIG", 46),
    "11": ("NSEC", 47),
    "12": ("NSEC3", 50),
    "13": ("DS", 43),
    "14": ("CAA", 257),
    "15": ("SRV", 33),
    "16": ("NAPTR", 35),
    "17": ("CERT", 37),
    "18": ("LOC", 29),
    "19": ("SSHFP", 44),
    "20": ("SPF", 99),
    "21": ("URI", 256),
    "22": ("SVCB", 64),
    "23": ("HTTPS", 65),
    "24": ("DNAME", 39),
    "25": ("ZONEMD", 63),
    "26": ("OPT", 41),
    "27": ("ANY", 255),
    "28": ("AXFR", 252)
}

# === 选择查询类型 ===
def select_query_type():
    print("\n📡 请选择查询类型：")
    print("=" * 90)
    print("🧩 普通查询类型 (1–28)：\n")

    keys = list(map(int, type_map.keys()))
    for i in range(0, len(keys), 4):
        part = keys[i:i+4]
        line = "   ".join([f"{k:>2}. {type_map[str(k)][0]}" for k in part])
        print(line)

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

# === 构造 DNS 请求包 ===
def build_dns_packet(query_name, query_type_val, dnssec=False, src_port=12345, dst_ip="8.8.8.8"):
    flags = 0x8000 if dnssec else 0x0000  # 设置 DO 位
    dns_layer = DNS(
        rd=1,
        qd=DNSQR(qname=query_name, qtype=query_type_val),
        ar=DNSRROPT(rclass=4096, z=flags)
    )
    udp_layer = UDP(sport=src_port, dport=53)
    ip_layer = IP(dst=dst_ip, ttl=64)
    return ip_layer / udp_layer / dns_layer

# === 测试单个 DNS 服务器 ===
def test_dns_server(server_ip, query_type_val, query_name, use_dnssec, src_port, query_method):
    pkt = build_dns_packet(query_name, query_type_val, use_dnssec, src_port, server_ip)
    try:
        req_size = len(raw(pkt))
        start = time.time()
        resp = sr1(pkt, timeout=TIMEOUT, verbose=0)
        end = time.time()

        if resp:
            resp_size = len(resp)
            amp_factor = round(resp_size / req_size, 2)
            return {
                "IP": server_ip,
                "Query Method": query_method,
                "Responded": "Yes",
                "Request Bytes": req_size,
                "Response Bytes": resp_size,
                "Amplification Factor": amp_factor,
                "Latency (s)": round(end - start, 3)
            }
        else:
            return {
                "IP": server_ip,
                "Query Method": query_method,
                "Responded": "No response",
                "Request Bytes": req_size,
                "Response Bytes": "",
                "Amplification Factor": 0,
                "Latency (s)": ""
            }

    except Exception as e:
        return {
            "IP": server_ip,
            "Query Method": query_method,
            "Responded": f"Error: {e.__class__.__name__}",
            "Request Bytes": "",
            "Response Bytes": "",
            "Amplification Factor": 0,
            "Latency (s)": ""
        }

# === 直接打印结果，不清屏 ===
def print_result_line(result):
    amp_val = result['Amplification Factor']
    amp_str = f"\033[92m{amp_val}\033[0m" if isinstance(amp_val, (int, float)) and amp_val > 0 else str(amp_val)
    print(f"{result['IP']:<16} {result['Query Method']:<15} {result['Responded']:<12} "
          f"{str(result['Request Bytes']):<8} {str(result['Response Bytes']):<9} "
          f"{amp_str:<8} {str(result['Latency (s)']):<10}")

# === 主程序 ===
def main():
    port_input = input("请输入源端口（默认 12345）: ").strip()
    src_port = int(port_input) if port_input.isdigit() else 12345

    query_name = TEST_DOMAIN
    qtype_name, qtype_val, use_dnssec = select_query_type()
    query_method = f"{qtype_name}{'+DNSSEC' if use_dnssec else ''}"

    print(f"\n📥 读取 DNS 列表文件: {INPUT_FILE}")
    try:
        with open(INPUT_FILE, "r") as f:
            servers = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"❌ 文件读取失败: {e}")
        return

    print(f"\n🔍 查询域名: {query_name} | 类型: {query_method} | 源端口: {src_port}")
    print(f"🌐 总服务器数: {len(servers)}\n")
    print(f"{'Server IP':<16} {'Query Method':<15} {'Resp':<12} {'Req(B)':<8} {'Resp(B)':<9} {'Amp':<8} {'Latency':<10}")
    print("-" * 90)

    results = []
    try:
        for idx, ip in enumerate(servers, 1):
            if interrupted:
                break
            result = test_dns_server(ip, qtype_val, query_name, use_dnssec, src_port, query_method)
            results.append(result)
            print_result_line(result)

    except KeyboardInterrupt:
        print("\n\n⚠️ 检测到中断，正在退出...")
        print(f"📊 已完成 {len(results)}/{len(servers)}")

    finally:
        print(f"\n✅ 测试结束，共测试 {len(results)} 个服务器")
        print(f"💡 建议监听命令：sudo tcpdump -i <interface> udp and dst port {src_port} -nn -v")

if __name__ == "__main__":
    main()
