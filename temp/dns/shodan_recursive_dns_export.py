from bs4 import BeautifulSoup
import os
import glob

# 📁 设置你的 HTML 文件目录
html_dir = "/home/dns/dns/"
output_path = "enabled_dns_ips_all.txt"

# 🔍 查找所有 HTML 文件 (*.html)
html_files = sorted(glob.glob(os.path.join(html_dir, "*.html")))

print(f"📂 共找到 {len(html_files)} 个 HTML 文件进行处理...\n")

enabled_ips = []

for file in html_files:
    print(f"📄 处理文件: {file}")
    with open(file, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")

    # 获取每个结果项的 IP 和 DNS 信息
    ip_tags = soup.select("div.result .heading a.title.text-dark")
    recursion_blocks = soup.select("div.result .banner-data pre")

    for ip_tag, block in zip(ip_tags, recursion_blocks):
        if "Recursion: enabled" in block.get_text():
            ip = ip_tag.get_text().strip()
            enabled_ips.append(ip)

# 去重（可选）
enabled_ips = sorted(set(enabled_ips))

# 输出结果
print(f"\n✅ 共提取到 {len(enabled_ips)} 个唯一 IP 地址（Recursion: enabled）:")
for ip in enabled_ips:
    print(ip)

# 写入输出文件
with open(output_path, "w") as f:
    f.write("\n".join(enabled_ips))

print(f"\n📁 所有结果已保存到: {output_path}")
