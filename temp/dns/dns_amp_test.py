import dns.message
import dns.rdatatype
import dns.exception
import time
import csv
import socket

# 配置
INPUT_FILE = "dns_list.txt"
OUTPUT_FILE = "dns_amplification_results.csv"
TEST_DOMAIN = "isc.org"
TIMEOUT = 2.0
SRC_PORT = 53535  # 指定的本地源端口（方便用 tcpdump 抓包）

# 查询类型菜单
def select_query_type():
    print("请选择查询类型：")
    print("1. ANY")
    print("2. TXT")
    print("3. MX")
    print("4. A")
    print("5. NS")
    print("6. DNSKEY")
    print("7. ANY +DNSSEC")
    print("8. TXT +DNSSEC")
    print("9. MX +DNSSEC")
    print("10. A +DNSSEC")
    print("11. NS +DNSSEC")
    print("12. DNSKEY +DNSSEC")

    choice = input("请输入数字 (默认 1): ").strip()
    type_map = {
        "1": (dns.rdatatype.ANY, False),
        "2": (dns.rdatatype.TXT, False),
        "3": (dns.rdatatype.MX, False),
        "4": (dns.rdatatype.A, False),
        "5": (dns.rdatatype.NS, False),
        "6": (dns.rdatatype.DNSKEY, False),
        "7": (dns.rdatatype.ANY, True),
        "8": (dns.rdatatype.TXT, True),
        "9": (dns.rdatatype.MX, True),
        "10": (dns.rdatatype.A, True),
        "11": (dns.rdatatype.NS, True),
        "12": (dns.rdatatype.DNSKEY, True)
    }
    return type_map.get(choice, (dns.rdatatype.ANY, False))

# 测试函数（绑定源端口 + 自定义 socket）
def test_dns_amplification(dns_ip, query_type, use_dnssec, src_port=SRC_PORT):
    query = dns.message.make_query(TEST_DOMAIN, query_type, want_dnssec=use_dnssec)
    query.use_edns(edns=True, payload=4096)
    query_data = query.to_wire()
    request_size = len(query_data)

    try:
        # 创建 UDP socket，绑定本地端口
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', src_port))
        sock.settimeout(TIMEOUT)

        start = time.time()
        sock.sendto(query_data, (dns_ip, 53))
        response_data, _ = sock.recvfrom(8192)
        end = time.time()
        response_size = len(response_data)

        # 解析响应（可选）
        try:
            dns.message.from_wire(response_data)
        except dns.exception.DNSException:
            pass  # 可忽略解析失败，只统计长度即可

        amplification = round(response_size / request_size, 2)
        return {
            "IP": dns_ip,
            "Responded": "Yes",
            "Request Bytes": request_size,
            "Response Bytes": response_size,
            "Amplification Factor": amplification,
            "Latency (s)": round(end - start, 3)
        }

    except Exception as e:
        return {
            "IP": dns_ip,
            "Responded": f"No ({e.__class__.__name__})",
            "Request Bytes": request_size,
            "Response Bytes": "",
            "Amplification Factor": "",
            "Latency (s)": ""
        }
    finally:
        sock.close()

# 主流程
def main():
    query_type, use_dnssec = select_query_type()
    print(f"\n📥 Reading DNS IPs from {INPUT_FILE} ...")
    with open(INPUT_FILE, "r") as f:
        dns_ips = [line.strip() for line in f if line.strip()]

    results = []
    type_name = dns.rdatatype.to_text(query_type)
    suffix = " +DNSSEC" if use_dnssec else ""
    print(f"🔍 Testing {len(dns_ips)} DNS server(s) with query: {TEST_DOMAIN} (type: {type_name}{suffix}) using source port {SRC_PORT}\n")

    for i, ip in enumerate(dns_ips, 1):
        print(f"[{i}/{len(dns_ips)}] Testing {ip} ...")
        result = test_dns_amplification(ip, query_type, use_dnssec)
        results.append(result)

    # 输出结果表格
    print("\n📊 Test Results:")
    print(f"{'IP':<16} {'Resp':<15} {'Req(B)':<8} {'Resp(B)':<10} {'Amp':<6} {'Latency(s)':<10}")
    for row in results:
        print(f"{row['IP']:<16} {row['Responded']:<15} {row['Request Bytes']:<8} {row['Response Bytes']:<10} {row['Amplification Factor']:<6} {row['Latency (s)']:<10}")

    # 写入 CSV 文件
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        fieldnames = ["IP", "Responded", "Request Bytes", "Response Bytes", "Amplification Factor", "Latency (s)"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"\n✅ All done. Results saved to: {OUTPUT_FILE}")
    print(f"🎯 建议监听命令：sudo tcpdump -i <interface> udp and dst port {SRC_PORT} -nn -v")

if __name__ == "__main__":
    main()
