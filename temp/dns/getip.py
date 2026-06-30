from bs4 import BeautifulSoup
import os
import re

# 配置路径
HTML_DIR = "/home/dns/dns1"  # 替换为你的 HTML 文件目录
OUTPUT_FILE = "newip1.txt"

# 用于保存所有提取到的 IP 地址
all_ips = set()

# 扫描目录下所有 .html 文件
for filename in os.listdir(HTML_DIR):
    if filename.endswith(".html"):
        filepath = os.path.join(HTML_DIR, filename)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            soup = BeautifulSoup(file, "html.parser")
            # 找出所有符合 class 要求的 <a> 标签
            links = soup.find_all("a", class_="title text-dark")
            for link in links:
                ip_text = link.get_text(strip=True)
                # 简单验证是否是 IP 格式
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip_text):
                    all_ips.add(ip_text)

# 写入结果
with open(OUTPUT_FILE, "w") as f:
    for ip in sorted(all_ips):
        f.write(ip + "\n")

print(f"✅ 提取完成，结果已保存到: {OUTPUT_FILE}")
