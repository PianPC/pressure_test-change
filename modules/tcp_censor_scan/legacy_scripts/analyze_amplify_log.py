import re
from collections import defaultdict
import numpy as np
from datetime import datetime
import os # 引入os模块用于处理路径

# --- 配置 ---
# 请根据实际日志文件的位置和期望的报告输出位置进行调整
# 示例：
# LOG_FILE_PATH = "/opt/project/scan_results/russia_SYN_PSH_yo_20251031_111534/amplify_ru-SYN_PSH-yo-test.txt"
# REPORT_FILE_PATH = "/opt/project/scan_results/russia_SYN_PSH_yo_20251031_111534/amplify50_ru-SYN_PSH-yo-test-report.txt"

# 默认值，如果命令行未提供，则使用这些
DEFAULT_LOG_FILE_PATH = "/opt/project/scan_results/trytest_SYN_PSH_ACK_yo_20251102_165211/magnification_test_SYN_PSH_ACK.log" # 假设日志文件与分析脚本在同目录
DEFAULT_REPORT_FILE_PATH = "/opt/project/scan_results/trytest_SYN_PSH_ACK_yo_20251102_165211/amplify_report_test_SYN_PSH_ACK.log"

# --- 排序权重配置 (总和建议为 1.0) ---
WEIGHTS = {
    'amplification': 0.5, # 对平均放大率的重视程度
    'stability': 0.3,     # 对稳定性的重视程度 (标准差越小越好，即稳定性越高)
    'success_rate': 0.2   # 对响应成功率的重视程度
}

def analyze_log(log_path):
    """
    解析日志文件并提取每个IP的放大率数据。
    同时，尝试从日志文件头部解析出配置信息。
    """
    ip_data = defaultdict(list)
    current_ip = None
    
    # 调整IP匹配模式以适应 test.py 的新日志格式
    # 匹配 "==== ... | 测试IP：1.2.3.4(...)"
    ip_pattern = re.compile(r"====.*?测试IP：([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    
    # 放大比率模式保持不变
    ratio_pattern = re.compile(r"📊 放大比率：([0-9]+\.[0-9]+)")

    # 配置信息匹配模式
    config_patterns = {
        '发包方式': re.compile(r"^- 发包方式：(.*?)\s*（对应方法编号：\d+）"),
        '敏感Payload': re.compile(r"^- 敏感Payload：(.*?)$"),
        'TTL': re.compile(r"^- TTL：(\d+)\s*\(通过命令行设置\)"),
        '扫描次数': re.compile(r"^- 单次IP扫描次数：(\d+)\s*\(通过命令行设置\)"),
    }
    extracted_config = {}
    config_parsed = False # 标记是否已解析配置信息

    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                # 尝试解析配置信息（只解析文件开头的几行）
                if not config_parsed:
                    for key, pattern in config_patterns.items():
                        match = pattern.search(line)
                        if match:
                            extracted_config[key] = match.group(1).strip()
                    if all(k in extracted_config for k in config_patterns): # 当所有配置项都找到后停止
                        config_parsed = True
                    # 如果读取到非配置信息行，也可以标记为停止解析配置
                    if line.strip().startswith("================") and not config_parsed:
                        config_parsed = True # 如果遇到分界线还没找到所有配置，也停止，避免误判
                        
                ip_match = ip_pattern.search(line)
                if ip_match:
                    current_ip = ip_match.group(1)
                    continue # 继续下一行
                
                if current_ip:
                    ratio_match = ratio_pattern.search(line)
                    if ratio_match:
                        ratio = float(ratio_match.group(1))
                        ip_data[current_ip].append(ratio)
    except FileNotFoundError:
        print(f"❌ 错误: 日志文件 '{log_path}' 未找到。请检查路径是否正确。")
        return None, None
    except Exception as e:
        print(f"❌ 错误: 读取或解析日志文件时发生异常: {e}")
        return None, None

    return ip_data, extracted_config

def calculate_stats(ip_data):
    """为每个IP计算详细的统计数据。"""
    stats = {}
    for ip, ratios in ip_data.items():
        # 过滤掉所有为0的ratio，计算成功响应（>0）的指标
        successful_ratios = [r for r in ratios if r > 0]
        
        num_samples = len(ratios) # 总的扫描次数
        successful_responses = len(successful_ratios) # 成功响应的次数
        success_rate = (successful_responses / num_samples) * 100 if num_samples > 0 else 0

        # 如果没有成功响应，则放大率相关指标为0，标准差NaN/0
        if not successful_ratios:
            stats[ip] = {
                'samples': num_samples,
                'success_rate': success_rate,
                'max_ratio': 0.0,
                'min_ratio': 0.0,
                'avg_ratio': 0.0,
                'median_ratio': 0.0,
                'std_dev': 0.0, # 如果没有成功响应，标准差为0
            }
        else:
            stats[ip] = {
                'samples': num_samples,
                'success_rate': success_rate,
                'max_ratio': np.max(successful_ratios),
                'min_ratio': np.min(successful_ratios),
                'avg_ratio': np.mean(successful_ratios),
                'median_ratio': np.median(successful_ratios),
                'std_dev': np.std(successful_ratios),
            }
    return stats

def rank_ips(stats):
    """根据综合评分对IP进行排序。"""
    # 过滤掉没有成功响应的IP，这些IP不参与排名
    rankable_stats = {ip: s for ip, s in stats.items() if s['success_rate'] > 0}

    if not rankable_stats:
        print("⚠️ 没有IP有成功响应，无法进行排名。")
        return []
    
    # 如果只有一个IP有成功响应，直接返回
    if len(rankable_stats) < 2:
        ip, s = list(rankable_stats.items())[0]
        s['score'] = s['avg_ratio'] # 只有一个IP时不计算复杂分数，直接用平均放大率作为分数
        return [(ip, s)]

    avg_ratios = [s['avg_ratio'] for s in rankable_stats.values()]
    std_devs = [s['std_dev'] for s in rankable_stats.values()]
    success_rates = [s['success_rate'] for s in rankable_stats.values()]

    # 归一化处理，避免除以零的情况
    min_avg, max_avg = min(avg_ratios), max(avg_ratios)
    min_std, max_std = min(std_devs), max(std_devs)
    min_succ, max_succ = min(success_rates), max(success_rates)

    ranked_list = []
    for ip, s in rankable_stats.items():
        # 如果某个指标的min和max相同，则归一化值为0 (例如所有IP平均放大率都一样)
        norm_avg = (s['avg_ratio'] - min_avg) / (max_avg - min_avg) if (max_avg - min_avg) > 0 else 0
        norm_std = 1 - ((s['std_dev'] - min_std) / (max_std - min_std) if (max_std - min_std) > 0 else 0) # 稳定性：标准差越小，归一化后值越大
        norm_succ = (s['success_rate'] - min_succ) / (max_succ - min_succ) if (max_succ - min_succ) > 0 else 0
        
        # 综合评分：放大率和成功率是正向指标，标准差是负向指标
        score = (WEIGHTS['amplification'] * norm_avg) \
              + (WEIGHTS['stability'] * norm_std) \
              + (WEIGHTS['success_rate'] * norm_succ)
        
        s['score'] = score
        ranked_list.append((ip, s))

    ranked_list.sort(key=lambda item: item[1]['score'], reverse=True)
    return ranked_list

def generate_report_header(log_file_path, report_file_path, extracted_config):
    """生成报告的头部信息，包含分析时间和从日志中提取的配置。"""
    header_lines = []
    header_lines.append("="*80)
    header_lines.append(f"      📡 TCP 放大率分析报告")
    header_lines.append(f"      生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    header_lines.append(f"      源日志文件: {log_file_path}")
    header_lines.append(f"      报告文件: {report_file_path}")
    header_lines.append(f"      分析权重: 放大率={WEIGHTS['amplification']}, 稳定性={WEIGHTS['stability']}, 成功率={WEIGHTS['success_rate']}")
    header_lines.append("-" * 80)
    
    if extracted_config:
        header_lines.append("      --- 测量配置 (从日志文件提取) ---")
        for key, value in extracted_config.items():
            # 为Payload特别处理，截断显示，避免过长
            if key == '敏感Payload' and len(value) > 100:
                value = value[:97] + "..." # 截断显示
            header_lines.append(f"      {key}: {value}")
        header_lines.append("-" * 80)
    else:
        header_lines.append("      ⚠️ 未能从日志文件头部提取到测量配置信息。")
        header_lines.append("-" * 80)

    return "\n".join(header_lines)

def generate_ranking_table_content(ranked_list):
    """生成格式化的、包含详细参数的排序表格字符串。"""
    report_lines = []
    report_lines.append("\n" + "="*110)
    report_lines.append("      🏆 IP 综合性能排序报告 (表格视图) 🏆")
    report_lines.append("="*110)
    
    header = (
        f"{'排名':<5}{'IP 地址':<18}{'综合得分':<12}{'平均放大':<11}"
        f"{'最大放大':<11}{'最小放大':<11}{'中位放大':<11}{'标准差':<11}{'成功率':<10}"
    )
    report_lines.append(header)
    report_lines.append(f"{'-'*4:<5}{'-'*17:<18}{'-'*10:<12}{'-'*9:<11}{'-'*9:<11}{'-'*9:<11}{'-'*9:<11}{'-'*9:<11}{'-'*9:<10}")

    for i, (ip, stats) in enumerate(ranked_list):
        rank = f"#{i+1}"
        score_str = f"{stats['score']:.3f}"
        avg_str = f"{stats['avg_ratio']:.2f}"
        max_str = f"{stats['max_ratio']:.2f}"
        min_str = f"{stats['min_ratio']:.2f}"
        median_str = f"{stats['median_ratio']:.2f}"
        std_str = f"{stats['std_dev']:.2f}"
        succ_str = f"{stats['success_rate']:.1f}%"
        
        row = (
            f"{rank:<5}{ip:<18}{score_str:<12}{avg_str:<11}"
            f"{max_str:<11}{min_str:<11}{median_str:<11}{std_str:<11}{succ_str:<10}"
        )
        report_lines.append(row)
    
    report_lines.append("="*110)
    return "\n".join(report_lines)

def generate_detailed_report_content(ranked_list, ip_data):
    """为每个IP生成一个更详细、易读的多行报告字符串。"""
    report_lines = []
    report_lines.append("\n" + "="*60)
    report_lines.append("      📋 IP 详细数据报告 (列表视图) 📋")
    report_lines.append("="*60)
    
    if not ranked_list:
        report_lines.append("\n  无IP数据可生成详细报告。")
        report_lines.append("\n" + "="*60)
        return "\n".join(report_lines)

    for i, (ip, stats) in enumerate(ranked_list):
        report_lines.append(f"\n--- 排名: #{i+1} | IP: {ip} ---")
        report_lines.append(f"  综合得分: {stats['score']:.3f}")
        report_lines.append("-" * 40)
        report_lines.append(f"  放大指标:")
        report_lines.append(f"    - 平均放大 (Average) : {stats['avg_ratio']:.2f}")
        report_lines.append(f"    - 中位放大 (Median)  : {stats['median_ratio']:.2f} (更能抵抗异常值)")
        report_lines.append(f"    - 峰值放大 (Max)     : {stats['max_ratio']:.2f}")
        report_lines.append(f"    - 谷值放大 (Min)     : {stats['min_ratio']:.2f}")
        report_lines.append(f"  稳定与可靠性:")
        report_lines.append(f"    - 标准差 (Stability) : {stats['std_dev']:.2f} (越小越稳定)")
        successful_count = sum(1 for r in ip_data.get(ip, []) if r > 0)
        report_lines.append(f"    - 成功率 (Success)   : {stats['success_rate']:.1f}% ({successful_count}/{stats['samples']})")

    report_lines.append("\n" + "="*60)
    report_lines.append("💡 解读: 综合得分越高，代表该IP的放大效果、稳定性、可靠性综合表现越好。")
    return "\n".join(report_lines)

if __name__ == "__main__":
    import sys

    # 允许从命令行指定日志文件和报告文件
    LOG_FILE_PATH = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_FILE_PATH
    REPORT_FILE_PATH = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_REPORT_FILE_PATH

    print("🚀 开始分析并排序TCP放大日志...")
    
    # 获取日志文件的父目录，以便生成默认报告文件时能与日志文件在同一目录
    if len(sys.argv) <= 2 and LOG_FILE_PATH == DEFAULT_LOG_FILE_PATH:
        # 如果用户没有提供任何参数，且使用了默认日志文件名
        # 此时REPORT_FILE_PATH可能也还是默认值，我们需要确保它与LOG_FILE_PATH位于同一目录
        script_dir = os.path.dirname(os.path.abspath(__file__))
        LOG_FILE_PATH = os.path.join(script_dir, DEFAULT_LOG_FILE_PATH)
        REPORT_FILE_PATH = os.path.join(script_dir, DEFAULT_REPORT_FILE_PATH)
    elif len(sys.argv) > 1 and len(sys.argv) <= 2:
        # 如果用户只提供了LOG_FILE_PATH，没有提供REPORT_FILE_PATH
        # 则将REPORT_FILE_PATH放到LOG_FILE_PATH所在的目录
        log_dir = os.path.dirname(os.path.abspath(LOG_FILE_PATH))
        report_filename = os.path.basename(REPORT_FILE_PATH) # 获取默认报告文件的名称
        REPORT_FILE_PATH = os.path.join(log_dir, report_filename)


    ip_data, extracted_config = analyze_log(LOG_FILE_PATH)
    
    if ip_data is not None: # 只有当日志解析成功时才继续
        ip_stats = calculate_stats(ip_data)
        ranked_ips = rank_ips(ip_stats)
        
        # --- 1. 生成报告内容 ---
        report_header = generate_report_header(LOG_FILE_PATH, REPORT_FILE_PATH, extracted_config)
        table_report_content = generate_ranking_table_content(ranked_ips)
        detailed_report_content = generate_detailed_report_content(ranked_ips, ip_data)
        
        # --- 2. 将报告打印到屏幕 ---
        print("\n" + report_header)
        print("\n" + table_report_content)
        print("\n" + detailed_report_content)
        
        # --- 3. 将报告保存到文件 ---
        try:
            with open(REPORT_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write(report_header)
                f.write("\n\n") # 增加一些间距
                f.write(table_report_content)
                f.write("\n\n\n") # 增加一些间距
                f.write(detailed_report_content)
            
            print(f"\n[✓] 分析报告已成功保存到文件: {REPORT_FILE_PATH}")

        except Exception as e:
            print(f"\n[✗] 保存报告文件失败: {e}")
    else:
        print("\n[✗] 日志文件分析失败，未能生成报告。")

