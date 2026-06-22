from scapy.all import IP, TCP, send, sniff, Raw
from datetime import datetime
import geoip2.database
import time
import subprocess
import re
import sys
import shutil # 引入shutil用于检查命令是否存在

# === 固定配置（无需用户输入，根据实际环境调整路径） ===
sport = 12345
seq = 1000
geoip_db_path = "/opt/project/GeoLite2-City.mmdb"  # 确保该路径下有GeoIP数据库文件

# === 全局变量（通过命令行传参赋值，核心适配自动化） ===
target_file = ""       # 接收IP_take.py输出的IP文件路径
log_file = ""          # 放大率测量日志文件路径
sensitive_payload = "" # 含用户输入HOST的敏感Payload
method = 0             # 发包方式对应的方法编号（1-5，与METHOD_MAP映射）
# 新增默认TTL和扫描次数常量
DEFAULT_TTL = 64
DEFAULT_SCAN_COUNT = 1

# === 发包方式与方法编号的映射（严格匹配5种发包类型） ===
METHOD_MAP = {
    "SYN_PSH_ACK": 1,  # 对应原方法1：SYN ; PSH+ACK
    "SYN_PSH": 2,      # 对应原方法2：SYN ; PSH
    "PSH": 3,          # 对应原方法3：仅 PSH
    "PSH_ACK": 4,      # 对应原方法4：仅 PSH+ACK
    "SYN": 5           # 对应原方法5：仅 SYN（探测用）
}

# === GEOIP 初始化（失败不中断，仅提示） ===
try:
    reader = geoip2.database.Reader(geoip_db_path)
except Exception as e:
    print(f"⚠️ GEOIP数据库初始化失败：{str(e)}，后续无法获取IP所属国家")
    reader = None

def geoip_lookup(ip):
    """根据IP查询国家，查询失败返回Unknown"""
    if reader:
        try:
            return reader.city(ip).country.name
        except:
            return "Unknown"
    return "Unknown"

def log_line(text):
    """同时打印日志到控制台和写入日志文件"""
    # 确保 log_file 已经被初始化
    if 'log_file' in globals() and log_file:
        with open(log_file, "a", encoding='utf-8') as f:
            f.write(text + "\n")
    print(text)

def load_targets(path):
    """从TXT文件加载目标IP列表，过滤空行和无效IP"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            # 保留非空且符合IP格式的行（简单校验）
            targets = [
                line.strip() for line in f 
                if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', line.strip())
            ]
        if not targets:
            log_line("⚠️ 目标IP文件为空或无有效IP，终止测量")
            sys.exit(0)
        return targets
    except FileNotFoundError:
        log_line(f"❌ 目标IP文件不存在：{path}")
        sys.exit(1)
    except Exception as e:
        log_line(f"❌ 加载IP文件失败：{str(e)}")
        sys.exit(1)

def build_packets(ip, ttl):
    """根据method编号构建对应的TCP数据包"""
    packets = []
    if method == 1:
        # 方法1：SYN + PSH+ACK（带Payload）
        syn_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="S", seq=seq)
        psh_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="PA", seq=seq+1, ack=1)/Raw(load=sensitive_payload)
        packets = [syn_pkt, psh_pkt]
    elif method == 2:
        # 方法2：SYN + PSH（带Payload）
        syn_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="S", seq=seq)
        psh_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="P", seq=seq+1)/Raw(load=sensitive_payload)
        packets = [syn_pkt, psh_pkt]
    elif method == 3:
        # 方法3：仅PSH（带Payload）
        psh_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="P", seq=seq)/Raw(load=sensitive_payload)
        packets = [psh_pkt]
    elif method == 4:
        # 方法4：仅PSH+ACK（带Payload）
        psh_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="PA", seq=seq, ack=1)/Raw(load=sensitive_payload)
        packets = [psh_pkt]
    elif method == 5:
        # 方法5：仅SYN（无Payload，探测用）
        syn_pkt = IP(dst=ip, ttl=ttl)/TCP(dport=80, sport=sport, flags="S", seq=seq)
        packets = [syn_pkt]
    return packets

def get_traceroute_path(ip): # 修改函数名，更符合其功能
    """执行traceroute获取目标IP的跳数和路径中的所有IP，失败返回None和空列表"""
    path_ips = []
    
    # 增加 traceroute 命令存在性检查
    traceroute_cmd = shutil.which("traceroute")
    if not traceroute_cmd:
        log_line(f"❌ 错误：在系统PATH中找不到 'traceroute' 命令。请确保已安装并配置PATH。")
        return None, []

    try:
        # 简化traceroute参数：10秒超时、1次探测、最大64跳
        result = subprocess.run(
            [traceroute_cmd, "-n", "-w", "10", "-q", "1", "-m", "64", ip], # -n 表示不解析主机名，直接显示IP
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20
        )
        output = result.stdout.decode('utf-8', errors='ignore')
        log_line(f"🔍 traceroute到 {ip} 的输出：")
        
        # 解析每一跳
        hops = output.strip().split("\n")
        
        # 记录目标IP的跳数
        hop_to_target = None

        for line in hops:
            log_line(f"   {line}") # 打印每一行traceroute输出到日志
            match = re.search(r"^\s*(\d+)\s+([0-9.]+)", line) # 匹配跳数和IP地址，使用search更灵活
            if match:
                current_hop_num = int(match.group(1))
                current_hop_ip = match.group(2)
                path_ips.append(current_hop_ip)
                
                # 如果当前IP是目标IP，记录其跳数
                if current_hop_ip == ip:
                    hop_to_target = current_hop_num
            
        if not path_ips:
            log_line("⚠️ traceroute未获取到有效跳数或路径信息")
            return None, [] 
        
        return hop_to_target, path_ips
    except subprocess.TimeoutExpired:
        log_line(f"⚠️ traceroute超时（IP：{ip}）")
        return None, []
    except Exception as e:
        log_line(f"⚠️ traceroute执行失败（IP：{ip}）：{str(e)}")
        return None, []

def verify_middlebox_traceroute(ip):
    """通过traceroute验证中间盒是否存在"""
    log_line(f"🌍 开始中间盒探测（IP：{ip}）")
    
    # 调用新的函数获取跳数和路径IP列表
    hop_to_target, path_ips = get_traceroute_path(ip)
    
    if path_ips:
        log_line(f"🛣️ Traceroute路径：{' -> '.join(path_ips)}")
    else:
        log_line("❌ 未获取到traceroute路径信息，跳过中间盒验证")
        return

    if not hop_to_target or hop_to_target <= 1:
        log_line("❌ 目标跳数无效（<1），跳过中间盒验证")
        return
    
    # 测试“目标前一跳”的TTL（若有响应则说明存在中间盒）
    test_ttl = hop_to_target - 1
    log_line(f"→ 目标在第{hop_to_target}跳，测试TTL={test_ttl}的数据包响应")
    
    packets = build_packets(ip, test_ttl)
    for pkt in packets:
        send(pkt, verbose=0)  # 静默发送，不打印详细信息
    
    # 捕获目标IP的响应（4秒超时，最多5个包）
    def filter_resp(pkt):
        return IP in pkt and TCP in pkt and pkt[IP].src == ip and pkt[TCP].dport == sport
    
    responses = sniff(filter=f"tcp and src host {ip}", timeout=4, count=5, lfilter=filter_resp)
    
    if responses:
        log_line(f"✅ [中间盒存在] TTL={test_ttl}仍收到响应（非目标主机直接响应）")
    else:
        log_line(f"❌ [无中间盒] TTL={test_ttl}未收到响应")

def test_target(ip, ttl, count):
    """测试单个IP的放大率，返回成功响应次数"""
    country = geoip_lookup(ip)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line(f"\n==== {ts} | 测试IP：{ip}（{country}） | 扫描次数：{count} ====")
    
    total_success = 0
    for scan_idx in range(count):
        log_line(f"\n--- 第{scan_idx+1}/{count}次扫描 ---")
        # 1. 构建并发送数据包
        packets = build_packets(ip, ttl)
        total_sent_len = sum(len(bytes(pkt)) for pkt in packets)
        
        for pkt in packets:
            send(pkt, verbose=0)
        log_line(f"📤 发送数据包：{len(packets)}个 | 总发送大小：{total_sent_len} bytes")
        
        # 2. 捕获响应数据包
        def filter_resp(pkt):
            return IP in pkt and TCP in pkt and pkt[IP].src == ip and pkt[TCP].dport == sport
        
        responses = sniff(filter=f"tcp and src host {ip}", timeout=15, count=20, lfilter=filter_resp)
        
        # 3. 分析响应结果
        if not responses:
            log_line("❌ 未收到任何响应")
            continue
        
        total_recv_len = sum(len(bytes(pkt)) for pkt in responses)
        ttl_set = {pkt.ttl for pkt in responses}
        flags_list = [pkt.sprintf("%TCP.flags%") for pkt in responses]
        
        # 计算放大率（避免除以0）
        amplification_ratio = round(total_recv_len / total_sent_len, 2) if total_sent_len > 0 else 0.0
        
        log_line(f"📥 收到响应：{len(responses)}个 | 总接收大小：{total_recv_len} bytes")
        log_line(f"📊 放大比率：{amplification_ratio}（接收/发送）")
        log_line(f"🔍 响应详情：TTL={sorted(ttl_set)} | Flags={', '.join(flags_list)}")
        
        total_success += 1
        time.sleep(0.01)  # 避免短时间内发送过多数据包
    
    # 4. 验证中间盒（仅在至少1次成功响应后执行）
    if total_success > 0:
        verify_middlebox_traceroute(ip)
    
    log_line(f"\n--- 该IP扫描完成 | 成功响应：{total_success}/{count}次 ---")
    return total_success

def scan_ip_multiple_times(targets, ttl, count):
    """批量扫描所有目标IP，统计整体成功率"""
    total_targets = len(targets)
    total_success = 0
    
    log_line(f"\n🧪 开始批量扫描 | 总目标IP数：{total_targets} | TTL：{ttl} | 单次扫描次数：{count}")
    
    for idx, ip in enumerate(targets, 1):
        log_line(f"\n=== 正在扫描第{idx}/{total_targets}个IP ===")
        success = test_target(ip, ttl, count)
        total_success += success
        time.sleep(0.5)  # 扫描间隔，避免网络拥塞
    
    # 计算整体成功率
    overall_success_rate = round((total_success / (total_targets * count)) * 100, 2) if (total_targets * count) > 0 else 0.0
    log_line(f"\n📈 所有IP扫描完成 | 整体成功率：{overall_success_rate}%（{total_success}/{total_targets * count}次）")

def main():
    """主函数：解析命令行参数，启动全流程"""
    global target_file, log_file, sensitive_payload, method
    
    # 1. 解析命令行参数（现在需要6个参数：IP文件、Payload、日志文件、发包方式、TTL、扫描次数）
    if len(sys.argv) != 7: # args count increased from 5 to 7
        print("❌ 参数错误！正确使用方式：")
        print("python3 test.py <目标IP文件路径> <敏感Payload> <日志文件路径> <发包方式> <TTL> <扫描次数>")
        print("示例：python3 test.py ./sa-PSH-yo-IP.txt 'GET / HTTP/1.1\\r\\nHost: www.youporn.com\\r\\n...' ./amplify.log PSH 64 1")
        sys.exit(1)
    
    # 2. 赋值全局变量并校验 (前4个参数与之前一致)
    target_file = sys.argv[1]
    sensitive_payload = sys.argv[2].replace('\\r', '\r').replace('\\n', '\n')  # 还原转义的换行/回车
    log_file = sys.argv[3]
    pkt_method = sys.argv[4]

    # 校验发包方式是否合法
    if pkt_method not in METHOD_MAP:
        log_line(f"❌ 无效发包方式：{pkt_method}，仅支持：{list(METHOD_MAP.keys())}")
        sys.exit(1)
    method = METHOD_MAP[pkt_method]
    
    # 解析TTL和扫描次数参数 (sys.argv[5] 和 sys.argv[6])
    try:
        ttl = int(sys.argv[5])
        count = int(sys.argv[6])
        
        if not (1 <= ttl <= 255): # 更简洁的校验方式
            log_line(f"⚠️ 命令行参数TTL值无效（{ttl}），需在1-255之间，自动使用默认值 {DEFAULT_TTL}")
            ttl = DEFAULT_TTL
        if not (1 <= count <= 100): # 更简洁的校验方式
            log_line(f"⚠️ 命令行参数扫描次数无效（{count}），需在1-100之间，自动使用默认值 {DEFAULT_SCAN_COUNT}")
            count = DEFAULT_SCAN_COUNT
            
    except ValueError:
        log_line(f"⚠️ 命令行参数TTL或扫描次数格式无效，自动使用默认值：TTL={DEFAULT_TTL}，扫描次数={DEFAULT_SCAN_COUNT}")
        ttl = DEFAULT_TTL
        count = DEFAULT_SCAN_COUNT
    
    # 3. 初始化日志文件（覆盖写入开头信息）
    with open(log_file, "w", encoding='utf-8') as f:
        # 准备需要格式化的变量
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        escaped_payload_for_log = sensitive_payload.replace('\r', '\\r').replace('\n', '\\n')

        # 更新日志模板，以反映TTL和扫描次数是通过命令行设置的
        init_info_template = """=== TCP放大率测量日志 | 启动时间：{} ===
- 目标IP文件：{}
- 发包方式：{}（对应方法编号：{}）
- 敏感Payload：{}
- TTL：{} (通过命令行设置)
- 单次IP扫描次数：{} (通过命令行设置)
=========================================
"""
        init_info = init_info_template.format(
            current_time,
            target_file,
            pkt_method,
            method,
            escaped_payload_for_log,
            ttl,  # 使用解析到的TTL值
            count # 使用解析到的扫描次数值
        )
        f.write(init_info + "\n") # 添加一个换行符，确保后续内容不粘连
    
    # 4. 加载目标IP列表
    targets = load_targets(target_file)
    
    # 5. 原来的用户输入部分已被替换为命令行参数解析，此处直接进行第6步
    
    # 6. 启动批量扫描
    scan_ip_multiple_times(targets, ttl, count)
    log_line(f"\n[✓] 所有测量任务完成！完整日志已保存至：{log_file}")

def test():
    """测试函数：使用配置文件中的固定参数运行（直接运行脚本时使用）"""
    global target_file, log_file, sensitive_payload, method, geoip_db_path
    
    # ==================== 配置文件中的固定参数（直接写死，无需命令行输入） ====================
    # [GENERAL_CONFIG]
    OUTPUT_DIR = "/opt/project/scan_results/trytest_SYN_PSH_ACK_yo_20251103_122708"
    
    # [SCAN_CONFIG]
    IP_FILE = "/opt/project/scan_results/trytest_SYN_PSH_ACK_yo_20251103_122708/ru-SYN_PSH_ACK-IPs.txt"  # 待测IP集文件路径
    TARGET_HOST = "www.youporn.com"      # 目标HOST
    PKT_METHOD = "SYN_PSH_ACK"           # 发包方式
    SCAN_RATE = 2000                     # 扫描速率（脚本中未使用，保留配置）
    
    # [AMPLIFY_CONFIG]
    GEOIP_DB_PATH = "/opt/project/GeoLite2-City.mmdb"  # GeoIP数据库路径
    SCAN_COUNT = 30                                     # 单个IP扫描次数
    TTL = 255                                           # TTL值
    
    # [SCRIPT_CONFIG]（脚本中未使用，保留配置）
    PROCESS_PY = "/opt/project/process_test.py"
    IP_TAKE_PY = "/opt/project/IP_take.py"
    MAGNIFICATION_TEST_PY = "/opt/project/magnification_test.py"
    ANALYZE_AMPLIFY_LOG_PY = "/opt/project/analyze_amplify_log.py"
    # ======================================================================================
    
    # 1. 初始化核心参数
    target_file = IP_FILE  # 目标IP文件
    pkt_method = PKT_METHOD  # 发包方式
    ttl = TTL  # TTL值
    count = SCAN_COUNT  # 单个IP扫描次数
    
    # 2. 构建敏感Payload（与Shell脚本中的格式一致）
    sensitive_payload = f"GET / HTTP/1.1\r\nHost: {TARGET_HOST}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    
    # 3. 构建日志文件路径（与Shell脚本中的命名规则一致）
    log_file = f"{OUTPUT_DIR}/amplification_test_{PKT_METHOD}.log"
    
    # 4. 更新GeoIP数据库路径并重新初始化
    geoip_db_path = GEOIP_DB_PATH
    global reader
    try:
        reader = geoip2.database.Reader(geoip_db_path)
        log_line(f"✅ GEOIP数据库初始化成功（路径：{geoip_db_path}）")
    except Exception as e:
        log_line(f"⚠️ GEOIP数据库初始化失败：{str(e)}，后续无法获取IP所属国家")
        reader = None
    
    # 5. 校验发包方式
    if pkt_method not in METHOD_MAP:
        log_line(f"❌ 无效发包方式：{pkt_method}，仅支持：{list(METHOD_MAP.keys())}")
        sys.exit(1)
    method = METHOD_MAP[pkt_method]
    
    # 6. 校验参数合法性
    if not (1 <= ttl <= 255):
        log_line(f"⚠️ TTL值无效（{ttl}），需在1-255之间，自动使用默认值 {DEFAULT_TTL}")
        ttl = DEFAULT_TTL
    if not (1 <= count <= 100):
        log_line(f"⚠️ 扫描次数无效（{count}），需在1-100之间，自动使用默认值 {DEFAULT_SCAN_COUNT}")
        count = DEFAULT_SCAN_COUNT
    
    # 7. 确保输出目录存在（如果不存在则创建）
    import os
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        log_line(f"✅ 创建输出目录：{OUTPUT_DIR}")
    
    # 8. 初始化日志文件
    with open(log_file, "w", encoding='utf-8') as f:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        escaped_payload_for_log = sensitive_payload.replace('\r', '\\r').replace('\n', '\\n')

        init_info_template = """=== TCP放大率测量日志 | 启动时间：{} ===
- 目标IP文件：{}
- 发包方式：{}（对应方法编号：{}）
- 敏感Payload：{}
- TTL：{} (配置文件设置)
- 单次IP扫描次数：{} (配置文件设置)
- GeoIP数据库路径：{}
- 输出目录：{}
=========================================
"""
        init_info = init_info_template.format(
            current_time,
            IP_FILE,
            PKT_METHOD,
            method,
            escaped_payload_for_log,
            ttl,
            count,
            GEOIP_DB_PATH,
            OUTPUT_DIR
        )
        f.write(init_info + "\n")
    
    # 9. 加载目标IP列表
    targets = load_targets(target_file)
    
    # 10. 启动批量扫描
    scan_ip_multiple_times(targets, ttl, count)
    log_line(f"\n[✓] 所有测量任务完成！完整日志已保存至：{log_file}")

if __name__ == "__main__":
    main()
    #test()
