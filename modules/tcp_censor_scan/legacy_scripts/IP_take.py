import csv
import os

def extract_ips_to_txt(csv_file, txt_file):
    """从CSV文件提取IP地址并保存到TXT文件，保留原始顺序+自动去重。"""
    ip_list = []  # 记录原始顺序的IP列表
    ip_set = set()  # 仅用于去重判断，不影响顺序

    try:
        # 读取CSV文件并提取IP（保留原始顺序，自动去重）
        with open(csv_file, mode='r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)

            if 'saddr' not in csv_reader.fieldnames:
                print(f"错误：CSV文件 '{csv_file}' 中没有'saddr'列。请检查CSV文件格式。")
                return False

            for row in csv_reader:
                ip = row['saddr'].strip()
                if ip and ip not in ip_set:  # 确保IP非空且未重复
                    ip_list.append(ip)
                    ip_set.add(ip)  # 标记为已存在，避免后续重复

        if not ip_list:
            print(f"警告：在CSV文件 '{csv_file}' 中没有提取到任何有效的IP地址。")
            with open(txt_file, mode='w', encoding='utf-8') as file:
                pass
            print(f"已创建空文件 '{txt_file}'。")
            return True

        # 按CSV原始顺序写入TXT（无额外排序）
        with open(txt_file, mode='w', encoding='utf-8') as file:
            for ip in ip_list:
                file.write(f"{ip}\n")

        print(f"✅ 成功从 '{csv_file}' 提取 {len(ip_list)} 个去重后的IP地址（保留原始顺序），已保存到 '{txt_file}'。")
        return True

    except FileNotFoundError:
        print(f"❌ 错误：找不到文件 '{csv_file}'。请检查路径和文件名。")
        return False
    except KeyError as e:
        print(f"❌ 错误：CSV文件中缺失必要的列 '{e}'。请检查CSV头。")
        return False
    except Exception as e:
        print(f"❌ 处理文件 '{csv_file}' 时发生错误：{str(e)}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <csv_filename> <txt_filename>")
        sys.exit(1)
        
    csv_filename = sys.argv[1]
    txt_filename = sys.argv[2]
    extract_ips_to_txt(csv_filename, txt_filename)
