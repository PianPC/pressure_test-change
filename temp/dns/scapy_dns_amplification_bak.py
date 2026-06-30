from scapy.all import *
import time
import os
import signal
import sys

# === 配置 ===
TEST_DOMAIN = "ripe.net"
TIMEOUT = 2
INPUT_FILE = "extracted_ips.txt"

# 用于处理中断
interrupted = False

def signal_handler(sig, frame):
    """处理 Ctrl+C 信号"""
    global interrupted
    interrupted = True
    print("\n\n⚠️  检测到中断信号，正在安全退出...")
    sys.exit(0)

# 注册信号处理器
signal.signal(signal.SIGINT, signal_handler)

# 查询类型映射（扩展版）
type_map = {
    "1": ("ANY", 255),
    "2": ("TXT", 16),
    "3": ("MX", 15),
    "4": ("A", 1),
    "5": ("NS", 2),
    "6": ("DNSKEY", 48),
    "7": ("AAAA", 28),
    "8": ("SOA", 6),
    "9": ("CNAME", 5),
    "10": ("PTR", 12),
    "11": ("SRV", 33),
    "12": ("CAA", 257),
    "13": ("NAPTR", 35),
    "14": ("RRSIG", 46)
}

# === 选择查询类型 ===
def select_query_type():
    print("\n请选择查询类型：")
    print("=" * 50)
    print("基础查询类型:")
    print("  1. ANY        2. TXT        3. MX         4. A")
    print("  5. NS         6. DNSKEY     7. AAAA       8. SOA")
    print("  9. CNAME      10. PTR       11. SRV       12. CAA")
    print("  13. NAPTR     14. RRSIG")
    print("\n带 DNSSEC 查询 (15-28):")
    print("  15. ANY +DNSSEC       16. TXT +DNSSEC")
    print("  17. MX +DNSSEC        18. A +DNSSEC")
    print("  19. NS +DNSSEC        20. DNSKEY +DNSSEC")
    print("  21. AAAA +DNSSEC      22. SOA +DNSSEC")
    print("  23. CNAME +DNSSEC     24. PTR +DNSSEC")
    print("  25. SRV +DNSSEC       26. CAA +DNSSEC")
    print("  27. NAPTR +DNSSEC     28. RRSIG +DNSSEC")
    print("=" * 50)

    choice = input("请输入数字（默认1）: ").strip()
    base = int(choice) if choice in map(str, range(1, 29)) else 1
    use_dnssec = base > 14
    if use_dnssec:
        base -= 14
    qtype_name, qtype_val = type_map[str(base)]
    return qtype_name, qtype_val, use_dnssec

# === 构造 DNS 请求包 ===
def build_dns_packet(query_name, query_type_val, dnssec=False, src_port=12345, dst_ip="8.8.8.8"):
    flags = 0x8000 if dnssec else 0x0000

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

# === 动态显示结果 ===
def display_results(results, query_name, qtype_name, use_dnssec, src_port, total_servers, current_idx):
    """清屏并显示排序后的结果"""
    # 清屏
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("=" * 110)
    print(f"🔍 查询域名: {query_name} | 类型: {qtype_name}{' +DNSSEC' if use_dnssec else ''} | 源端口: {src_port}")
    print(f"🌐 总共测试服务器: {total_servers} | 已测试: {current_idx}/{total_servers}")
    print("=" * 110)
    print(f"{'Server IP':<16} {'Query Method':<15} {'Resp':<12} {'Req(B)':<8} {'Resp(B)':<9} {'Amp':<8} {'Latency':<10}")
    print("-" * 110)
    
    # 按放大倍数升序排序（最大值在最下面）
    sorted_results = sorted(results, key=lambda x: x.get('Amplification Factor', 0), reverse=False)
    
    for result in sorted_results:
        amp_val = result['Amplification Factor']
        # 绿色高亮显示放大倍数
        if isinstance(amp_val, (int, float)) and amp_val > 0:
            amp_str = f"\033[92m{amp_val}\033[0m"  # 绿色显示
        else:
            amp_str = str(amp_val)
            
        print(f"{result['IP']:<16} {result['Query Method']:<15} {result['Responded']:<12} "
              f"{str(result['Request Bytes']):<8} {str(result['Response Bytes']):<9} "
              f"{amp_str:<8} {str(result['Latency (s)']):<10}")
    
    print("=" * 110)

# === 主流程 ===
def main():
    # 用户输入源端口
    port_input = input("请输入源端口（默认 12345）: ").strip()
    if port_input.isdigit() and 1 <= int(port_input) <= 65535:
        src_port = int(port_input)
    else:
        src_port = 12345

    # 然后选择查询类型
    query_name = TEST_DOMAIN
    qtype_name, qtype_val, use_dnssec = select_query_type()
    query_method = f"{qtype_name}{'+DNSSEC' if use_dnssec else ''}"

    print(f"\n📥 读取 DNS 列表: {INPUT_FILE}")
    with open(INPUT_FILE, "r") as f:
        servers = [line.strip() for line in f if line.strip()]

    print(f"\n💡 提示：随时按 Ctrl+C 可以安全退出测试\n")
    time.sleep(1)  # 给用户时间看到提示
    
    results = []
    try:
        for idx, ip in enumerate(servers, 1):
            if interrupted:
                break
            
            result = test_dns_server(ip, qtype_val, query_name, use_dnssec, src_port, query_method)
            results.append(result)
            
            # 每次测试后动态显示结果（按Amp排序）
            display_results(results, query_name, qtype_name, use_dnssec, src_port, len(servers), idx)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  检测到中断 (Ctrl+C)，正在退出...")
        print(f"\n📊 已完成 {len(results)}/{len(servers)} 个服务器的测试")
    
    finally:
        if results:
            print(f"\n✅ 测试{'完成' if len(results) == len(servers) else '中断'}")
            print(f"   共测试了 {len(results)} 个服务器")
            print(f"\n💡 建议使用命令监听：")
            print(f"   sudo tcpdump -i <interface> udp and dst port {src_port} -nn -v")
        else:
            print("\n❌ 未完成任何测试")

if __name__ == "__main__":
    main()
