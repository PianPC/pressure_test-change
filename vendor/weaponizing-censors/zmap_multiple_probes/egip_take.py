def extract_non_zero_payload(input_txt_path, output_txt_path):
    """
    提取TXT文件中payloadlen不为0的行
    :param input_txt_path: 输入TXT文件路径（源数据文件）
    :param output_txt_path: 输出TXT文件路径（保存结果的文件）
    """
    # 1. 读取输入文件并筛选目标行
    with open(input_txt_path, 'r', encoding='utf-8') as input_file:
        # 读取所有行，去除每行前后的空白字符（避免换行符/空格干扰）
        all_lines = [line.strip() for line in input_file if line.strip()]

    if not all_lines:
        print(f"❌ 输入文件 {input_txt_path} 为空或无有效内容")
        return

    # 2. 筛选 payloadlen 不为 0 的行（保留第一行标题）
    target_lines = []
    # 处理第一行标题（直接加入结果，不筛选）
    header = all_lines[0]
    target_lines.append(header)

    # 检查标题是否包含 "payloadlen"（确保文件格式正确）
    if "payloadlen" not in header:
        print(f"⚠️  警告：输入文件第一行未找到 'payloadlen' 字段，可能格式错误！")
        print(f"   标题行内容：{header}")
        # 仍继续执行，但后续筛选可能失效，需用户确认文件格式

    # 找到 "payloadlen" 对应的列索引（用于后续判断数值）
    try:
        # 按制表符分割标题（你的数据是制表符分隔，不是逗号）
        header_columns = header.split(',')
        payload_col_index = header_columns.index("payloadlen")
    except ValueError:
        print(f"❌ 错误：无法在标题中找到 'payloadlen' 字段，无法筛选！")
        return

    # 处理数据行（从第二行开始）
    for line in all_lines[1:]:
        # 按制表符分割数据（你的数据格式是制表符分隔，不是逗号）
        data_columns = line.split(',')
        # 确保当前行的列数与标题一致（避免数据格式异常）
        if len(data_columns) != len(header_columns):
            print(f"⚠️  跳过格式异常的行：{line}（列数与标题不匹配）")
            continue

        # 获取当前行的 payloadlen 值
        payload_value = data_columns[payload_col_index].strip()
        # 判断 payloadlen 是否为非零数值
        try:
            # 转为整数（若无法转整数，说明是无效数据，跳过）
            payload_num = int(payload_value)
            if payload_num != 0:
                # 非零则加入结果
                target_lines.append(line)
        except ValueError:
            print(f"⚠️  跳过无效数据行：{line}（payloadlen 字段 '{payload_value}' 不是整数）")
            continue

    # 3. 将筛选结果写入输出文件
    with open(output_txt_path, 'w', encoding='utf-8') as output_file:
        # 每行末尾添加换行符，保持文件格式规范
        output_file.write('\n'.join(target_lines))

    # 4. 打印执行结果
    print(f"✅ 提取完成！")
    print(f"📊 统计：")
    print(f"   - 输入文件总行数（含标题）：{len(all_lines)}")
    print(f"   - 输出文件总行数（含标题）：{len(target_lines)}")
    print(f"   - 提取的非零 payloadlen 数据行数：{len(target_lines) - 1}")  # 减去标题行
    print(f"   - 结果保存路径：{output_txt_path}")


# ------------------- 配置参数（用户可根据实际情况修改） -------------------
INPUT_FILE = "eg_result.csv"    # 你的输入TXT文件路径（即使后缀是.csv，实际是制表符分隔的TXT）
OUTPUT_FILE = "eg_long.txt" # 输出结果文件路径（自定义名称）
# -------------------------------------------------------------------------

# 执行提取
if __name__ == "__main__":
    extract_non_zero_payload(INPUT_FILE, OUTPUT_FILE)
