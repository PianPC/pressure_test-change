#!/usr/bin/env python3
"""
DNS服务器TXT+DNSSEC性能评估工具
专门测试公共DNS服务器对TXT记录和DNSSEC查询的响应能力
"""

import socket
import time
import threading
import random
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics
import json
import csv
from datetime import datetime
import sys

class TXTDNSECBenchmark:
    def __init__(self, dns_servers_file="dns_servers.txt", duration=15, threads=5):
        self.dns_servers = self.load_dns_servers(dns_servers_file)
        self.duration = duration
        self.threads = threads
        self.results = {}
        self.lock = threading.Lock()
        
        # 专门针对TXT+DNSSEC优化的测试域名
        self.test_domains = [
            "ripe.net",           # RIPE NCC - 大量TXT记录和完整DNSSEC
            "isc.org",            # Internet Systems Consortium
            "dns-oarc.net",       # DNS运营、分析和研究中心
            "iana.org",           # IANA - 互联网数字分配机构
            "arin.net",           # ARIN - 北美IP注册机构
            "apnic.net",          # APNIC - 亚太地区IP注册机构
            "verisignlabs.com",   # Verisign实验室
            "cloudflare.com",     # Cloudflare
            "google.com",         # Google
            "facebook.com"        # Facebook
        ]
        
    def load_dns_servers(self, filename):
        """加载DNS服务器列表"""
        try:
            with open(filename, 'r') as f:
                servers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"✅ 已加载 {len(servers)} 个DNS服务器")
            return servers
        except FileNotFoundError:
            print(f"❌ 找不到DNS服务器文件: {filename}")
            sys.exit(1)
    
    def build_txt_dnssec_query(self, domain="ripe.net"):
        """构建TXT+DNSSEC查询包"""
        # DNS头部 - 设置DO位(DNSSEC OK)
        transaction_id = random.randint(0, 65535)
        flags = 0x0100  # 标准查询
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 1  # 添加OPT记录用于DNSSEC
        
        dns_header = struct.pack('!HHHHHH', 
                               transaction_id, flags, questions, 
                               answer_rrs, authority_rrs, additional_rrs)
        
        # DNS查询部分 - TXT记录
        qname_parts = domain.split('.')
        qname = b''
        for part in qname_parts:
            qname += struct.pack('B', len(part)) + part.encode()
        qname += b'\x00'  # 结束
        
        qtype = struct.pack('!H', 16)  # TXT记录类型
        qclass = struct.pack('!H', 1)  # IN class
        
        dns_query = qname + qtype + qclass
        
        # OPT记录（用于DNSSEC）- 设置DO位
        opt_name = b'\x00'  # 根域名
        opt_type = struct.pack('!H', 41)  # OPT
        udp_payload_size = struct.pack('!H', 4096)  # 扩展UDP大小
        extended_rcode = 0
        edns_version = 0
        z = 0x8000  # DNSSEC OK flag (DO位)
        opt_rdlen = struct.pack('!H', 0)  # 空RDATA
        
        opt_record = (opt_name + opt_type + udp_payload_size + 
                     struct.pack('!B', extended_rcode) + 
                     struct.pack('!B', edns_version) + 
                     struct.pack('!H', z) + opt_rdlen)
        
        return dns_header + dns_query + opt_record
    
    def calculate_amplification_factor(self, query_size, response_size):
        """计算放大倍数"""
        if query_size > 0:
            return response_size / query_size
        return 0
    
    def test_single_server_domain_combo(self, server, domain, test_duration=10):
        """测试单个DNS服务器对特定域名的TXT+DNSSEC性能"""
        print(f"🔍 测试 {server} -> {domain} (TXT+DNSSEC)")
        
        stats = {
            'server': server,
            'domain': domain,
            'total_queries': 0,
            'successful_responses': 0,
            'failed_responses': 0,
            'response_times': [],
            'amplification_factors': [],
            'avg_amplification': 0,
            'max_amplification': 0,
            'response_sizes': [],
            'start_time': time.time(),
            'max_qps': 0,
            'avg_response_time': 0,
            'reliability': 0
        }
        
        try:
            # 创建UDP套接字
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)  # 增加超时时间，因为DNSSEC查询可能较慢
            
            # 构建TXT+DNSSEC查询
            query_data = self.build_txt_dnssec_query(domain)
            query_size = len(query_data)
            
            end_time = time.time() + test_duration
            query_count = 0
            
            while time.time() < end_time:
                query_count += 1
                start_query = time.time()
                
                try:
                    # 发送查询
                    sock.sendto(query_data, (server, 53))
                    
                    # 接收响应
                    data, addr = sock.recvfrom(65535)  # 增加缓冲区大小
                    response_time = (time.time() - start_query) * 1000  # 转换为毫秒
                    
                    if data and len(data) > 12:  # 有效的DNS响应
                        stats['successful_responses'] += 1
                        stats['response_times'].append(response_time)
                        
                        # 计算放大倍数
                        response_size = len(data)
                        amplification = self.calculate_amplification_factor(query_size, response_size)
                        stats['amplification_factors'].append(amplification)
                        stats['response_sizes'].append(response_size)
                        
                    else:
                        stats['failed_responses'] += 1
                        
                except socket.timeout:
                    stats['failed_responses'] += 1
                except Exception as e:
                    stats['failed_responses'] += 1
                
                stats['total_queries'] = query_count
                
                # 计算当前QPS
                elapsed = time.time() - stats['start_time']
                current_qps = query_count / elapsed if elapsed > 0 else 0
                stats['max_qps'] = max(stats['max_qps'], current_qps)
                
                # 避免过度占用CPU，但保持较高频率以测试最大QPS
                time.sleep(0.005)
            
            sock.close()
            
        except Exception as e:
            print(f"❌ 测试 {server} -> {domain} 时出错: {e}")
            stats['error'] = str(e)
        
        # 计算统计信息
        if stats['response_times']:
            stats['avg_response_time'] = statistics.mean(stats['response_times'])
            stats['min_response_time'] = min(stats['response_times'])
            stats['max_response_time'] = max(stats['response_times'])
            stats['std_dev'] = statistics.stdev(stats['response_times']) if len(stats['response_times']) > 1 else 0
        else:
            stats['avg_response_time'] = 0
            stats['min_response_time'] = 0
            stats['max_response_time'] = 0
            stats['std_dev'] = 0
        
        # 计算放大倍数统计
        if stats['amplification_factors']:
            stats['avg_amplification'] = statistics.mean(stats['amplification_factors'])
            stats['max_amplification'] = max(stats['amplification_factors'])
            stats['avg_response_size'] = statistics.mean(stats['response_sizes'])
        else:
            stats['avg_amplification'] = 0
            stats['max_amplification'] = 0
            stats['avg_response_size'] = 0
        
        stats['reliability'] = (stats['successful_responses'] / stats['total_queries'] * 100) if stats['total_queries'] > 0 else 0
        
        return stats
    
    def benchmark_all_servers(self):
        """对所有DNS服务器和测试域名进行TXT+DNSSEC性能测试"""
        print(f"🚀 开始TXT+DNSSEC性能测试")
        print(f"⏱️  持续时间: {self.duration}秒, 线程数: {self.threads}")
        print(f"🌐 测试域名: {', '.join(self.test_domains)}")
        
        all_results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for domain in self.test_domains:
                print(f"\n🎯 测试域名: {domain}")
                
                # 提交所有服务器的测试任务
                future_to_server = {
                    executor.submit(self.test_single_server_domain_combo, server, domain, self.duration): server 
                    for server in self.dns_servers
                }
                
                domain_results = []
                completed = 0
                total = len(self.dns_servers)
                
                for future in as_completed(future_to_server):
                    server = future_to_server[future]
                    try:
                        result = future.result()
                        domain_results.append(result)
                        
                        completed += 1
                        if result['successful_responses'] > 0:
                            print(f"📈 {completed}/{total} - {server}: {result['max_qps']:.1f} QPS, "
                                  f"放大: {result['avg_amplification']:.1f}x, 可靠: {result['reliability']:.1f}%")
                        else:
                            print(f"❌ {completed}/{total} - {server}: 无响应")
                        
                    except Exception as e:
                        print(f"❌ {server} 测试失败: {e}")
                        domain_results.append({
                            'server': server,
                            'domain': domain,
                            'error': str(e),
                            'max_qps': 0,
                            'reliability': 0,
                            'avg_amplification': 0
                        })
                
                # 按QPS排序
                domain_results.sort(key=lambda x: x['max_qps'], reverse=True)
                all_results[domain] = domain_results
        
        self.results = all_results
        return all_results
    
    def generate_report(self, output_format="text"):
        """生成TXT+DNSSEC专用测试报告"""
        if not self.results:
            print("❌ 没有测试结果可报告")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format == "json":
            filename = f"txt_dnssec_benchmark_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"📄 JSON报告已保存: {filename}")
        
        elif output_format == "csv":
            filename = f"txt_dnssec_benchmark_{timestamp}.csv"
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Server', 'Max QPS', 'Avg Amplification', 
                               'Max Amplification', 'Avg Response Time (ms)', 'Reliability (%)', 
                               'Avg Response Size', 'Total Queries', 'Successful', 'Failed'])
                
                for domain, servers in self.results.items():
                    for server_data in servers:
                        writer.writerow([
                            domain,
                            server_data['server'],
                            f"{server_data['max_qps']:.2f}",
                            f"{server_data['avg_amplification']:.2f}",
                            f"{server_data['max_amplification']:.2f}",
                            f"{server_data['avg_response_time']:.2f}",
                            f"{server_data['reliability']:.2f}",
                            f"{server_data.get('avg_response_size', 0):.2f}",
                            server_data['total_queries'],
                            server_data['successful_responses'],
                            server_data['failed_responses']
                        ])
            print(f"📄 CSV报告已保存: {filename}")
        
        # 文本报告（控制台输出）
        print("\n" + "="*100)
        print("🎯 TXT+DNSSEC DNS服务器性能评估报告")
        print("="*100)
        
        for domain, servers in self.results.items():
            # 过滤出有响应的服务器
            responding_servers = [s for s in servers if s['successful_responses'] > 0]
            
            if not responding_servers:
                print(f"\n📊 域名: {domain} - 无响应服务器")
                continue
                
            print(f"\n📊 域名: {domain}")
            print("-" * 100)
            print(f"{'排名':<4} {'服务器':<20} {'最大QPS':<10} {'平均放大':<12} {'最大放大':<12} {'平均延迟':<12} {'可靠性':<10}")
            print("-" * 100)
            
            for i, server_data in enumerate(responding_servers[:15], 1):  # 只显示前15名
                print(f"{i:<4} {server_data['server']:<20} {server_data['max_qps']:<10.1f} "
                      f"{server_data['avg_amplification']:<12.1f} {server_data['max_amplification']:<12.1f} "
                      f"{server_data['avg_response_time']:<12.1f} {server_data['reliability']:<10.1f}")
            
            # 显示统计摘要
            if len(responding_servers) > 0:
                avg_qps = statistics.mean([s['max_qps'] for s in responding_servers])
                avg_amp = statistics.mean([s['avg_amplification'] for s in responding_servers])
                max_amp = max([s['max_amplification'] for s in responding_servers])
                high_amp_servers = [s for s in responding_servers if s['avg_amplification'] > 10]
                
                print(f"\n📈 {domain} 统计摘要:")
                print(f"   • 响应服务器: {len(responding_servers)}/{len(servers)}")
                print(f"   • 平均最大QPS: {avg_qps:.1f}")
                print(f"   • 平均放大倍数: {avg_amp:.1f}x")
                print(f"   • 最大放大倍数: {max_amp:.1f}x")
                print(f"   • 高放大服务器(>10x): {len(high_amp_servers)}个")
    
    def get_amplification_optimized_servers(self, min_reliability=80, min_amplification=5):
        """获取针对放大优化的DNS服务器推荐"""
        optimized_servers = {}
        
        for domain, servers in self.results.items():
            # 筛选可靠且放大倍数高的服务器
            good_servers = [
                s for s in servers 
                if s.get('reliability', 0) >= min_reliability and 
                   s.get('avg_amplification', 0) >= min_amplification
            ]
            
            # 按放大倍数排序
            good_servers.sort(key=lambda x: x['avg_amplification'], reverse=True)
            optimized_servers[domain] = good_servers[:20]  # 每个域名返回前20个
        
        return optimized_servers
    
    def generate_pressure_test_config(self, output_file="pressure_test_servers.txt"):
        """生成用于压力测试的优化服务器配置"""
        optimized = self.get_amplification_optimized_servers()
        
        # 合并所有域名的优质服务器，按放大倍数排序
        all_servers = []
        for domain_servers in optimized.values():
            all_servers.extend(domain_servers)
        
        # 去重并按放大倍数排序
        unique_servers = {}
        for server_data in all_servers:
            server_ip = server_data['server']
            if server_ip not in unique_servers or server_data['avg_amplification'] > unique_servers[server_ip]['avg_amplification']:
                unique_servers[server_ip] = server_data
        
        sorted_servers = sorted(unique_servers.values(), key=lambda x: x['avg_amplification'], reverse=True)
        
        # 保存到文件
        with open(output_file, 'w') as f:
            f.write("# TXT+DNSSEC压力测试优化服务器列表\n")
            f.write("# 生成时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("# 格式: 服务器IP,平均放大倍数,最大QPS,可靠性%\n")
            
            for server_data in sorted_servers[:100]:  # 保存前100个最佳服务器
                f.write("{},{:.1f},{:.1f},{:.1f}\n".format(
                    server_data['server'],
                    server_data['avg_amplification'],
                    server_data['max_qps'],
                    server_data['reliability']
                ))
        
        print(f"🎯 压力测试配置文件已生成: {output_file}")
        print(f"📊 包含 {len(sorted_servers[:100])} 个优化服务器")
        
        return sorted_servers[:100]

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="TXT+DNSSEC DNS服务器性能评估工具")
    parser.add_argument("--servers", default="niceip.txt", help="DNS服务器列表文件")
    parser.add_argument("--duration", type=int, default=15, help="每个服务器测试时长(秒)")
    parser.add_argument("--threads", type=int, default=5, help="并发线程数")
    parser.add_argument("--output", choices=["text", "json", "csv", "all"], default="text", help="输出格式")
    parser.add_argument("--generate-config", action="store_true", help="生成压力测试配置文件")
    
    args = parser.parse_args()
    
    # 创建评估器
    benchmark = TXTDNSECBenchmark(
        dns_servers_file=args.servers,
        duration=args.duration,
        threads=args.threads
    )
    
    # 运行性能测试
    print("🚀 开始TXT+DNSSEC专用性能测试...")
    results = benchmark.benchmark_all_servers()
    
    # 生成报告
    if args.output in ["text", "all"]:
        benchmark.generate_report("text")
    
    if args.output in ["json", "all"]:
        benchmark.generate_report("json")
    
    if args.output in ["csv", "all"]:
        benchmark.generate_report("csv")
    
    # 显示推荐服务器
    optimized = benchmark.get_amplification_optimized_servers()
    print("\n🎯 TXT+DNSSEC高性能DNS服务器推荐:")
    
    for domain, servers in optimized.items():
        if servers:
            print(f"\n🌐 {domain} - 前3个推荐服务器:")
            for i, server in enumerate(servers[:3], 1):
                print(f"  {i}. {server['server']} (放大: {server['avg_amplification']:.1f}x, "
                      f"QPS: {server['max_qps']:.1f}, 可靠: {server['reliability']:.1f}%)")
    
    # 生成压力测试配置
    if args.generate_config:
        pressure_servers = benchmark.generate_pressure_test_config()
        print(f"\n💥 压力测试准备就绪!")
        print(f"📊 最佳服务器: {pressure_servers[0]['server']} "
              f"(放大: {pressure_servers[0]['avg_amplification']:.1f}x)")

if __name__ == "__main__":
    main()