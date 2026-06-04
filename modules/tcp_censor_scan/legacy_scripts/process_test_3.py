import csv
import sqlite3
import os
import sys
import uuid
import hashlib

# 修改函数签名，添加 length_threshold 参数，默认值为 1000
def process_csv_optimized(input_file, output_file, limit_count=None, length_threshold=1000):
    # 关键步骤：获取output_file所在的文件夹路径
    output_dir = os.path.dirname(output_file)
    # 若output_file是纯文件名（无路径），则用当前工作目录
    if not output_dir:
        output_dir = os.getcwd()
    
    # 生成输入文件的唯一哈希（关联输入文件，避免冲突）
    with open(input_file, 'rb') as f:
        # 这里只读取文件开头，若文件太大，可考虑只对文件名和部分内容哈希
        file_hash = hashlib.md5(f.read(1024)).hexdigest()[:10]
    # 构造DB文件名，放入output_file相同文件夹
    db_file = os.path.join(output_dir, f"packet_data_{file_hash}_{uuid.uuid4().hex[:6]}.db")
    
    # 仅当DB不存在时创建（保留历史DB）
    if os.path.exists(db_file):
        print(f"Found existing DB: {db_file}, reusing it")
    else:
        print(f"Creating new DB in output folder: {db_file}")
    
    # 后续数据库操作逻辑不变
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packet_summary (
            saddr TEXT PRIMARY KEY,
            total_len INTEGER,
            total_payloadlen INTEGER,
            flags_str TEXT,
            packet_count INTEGER
        );
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saddr_flags (
            saddr TEXT,
            flag_value TEXT,
            PRIMARY KEY (saddr, flag_value)
        );
    ''')
    conn.commit()

    print(f"Processing input file: {input_file}...")

    batch_size = 10000
    batch_data_for_summary = {}
    batch_data_for_flags = {}

    with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        row_count = 0
        for row in reader:
            row_count += 1
            saddr = row['saddr']

            if saddr not in batch_data_for_summary:
                batch_data_for_summary[saddr] = {
                    'total_len': 0,
                    'total_payloadlen': 0,
                    'count': 0
                }
                batch_data_for_flags[saddr] = set()

            batch_data_for_summary[saddr]['total_len'] += int(row['len'])
            batch_data_for_summary[saddr]['total_payloadlen'] += int(row['payloadlen'])
            batch_data_for_summary[saddr]['count'] += 1
            batch_data_for_flags[saddr].add(row['flags'])

            if len(batch_data_for_summary) >= batch_size:
                _commit_batch_to_db(conn, cursor, batch_data_for_summary, batch_data_for_flags)
                batch_data_for_summary.clear()
                batch_data_for_flags.clear()
                print(f"Processed {row_count} rows, committing batch to DB...")

        if batch_data_for_summary:
            _commit_batch_to_db(conn, cursor, batch_data_for_summary, batch_data_for_flags)
            print(f"Processed {row_count} total rows, committing final batch to DB.")

    print("Querying and sorting results from database...")
    
    # === 修改这部分逻辑，根据 length_threshold 和 limit_count 动态构建查询 ===
    sql_template = '''
        SELECT saddr, total_len, total_payloadlen, flags_str, packet_count
        FROM packet_summary
        WHERE total_len > ?
        ORDER BY total_len DESC
    '''
    query_params = [length_threshold] # 第一个参数永远是 length_threshold

    # 如果 limit_count 有效（非 None 且大于 0），则添加 LIMIT 子句
    if limit_count is not None and limit_count > 0:
        sql_query = sql_template + f"\nLIMIT ?;"
        query_params.append(limit_count)
        print(f"Querying top {limit_count} entries with total length > {length_threshold}.")
    else:
        sql_query = sql_template + ";"
        print(f"Querying all entries with total length > {length_threshold}.")

    cursor.execute(sql_query, tuple(query_params)) # 使用 tuple(query_params) 传递参数
    filtered_result_db = cursor.fetchall()
    
    final_data_to_write = []
    if filtered_result_db:
        final_data_to_write = [_convert_db_row_to_dict(row) for row in filtered_result_db]
        limit_msg = f" (limited to {limit_count})" if limit_count and limit_count > 0 else ""
        print(f"Found {len(final_data_to_write)} entries with total length > {length_threshold}{limit_msg}.")
    else:
        cursor.execute('''
            SELECT saddr, total_len, total_payloadlen, flags_str, packet_count
            FROM packet_summary
            ORDER BY total_len DESC
            LIMIT 10;
        ''')
        top10_result_db = cursor.fetchall()
        final_data_to_write = [_convert_db_row_to_dict(row) for row in top10_result_db]
        print(f"No entries with total length > {length_threshold}. Keeping the top 10 entries instead.")

    print(f"Writing results to output file: {output_file}...")
    with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        fieldnames = ['saddr', 'len', 'payloadlen', 'flags', 'count']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in final_data_to_write:
            writer.writerow(row)

    conn.close()
    print(f"DB retained in output folder: {db_file}")

def _commit_batch_to_db(conn, cursor, batch_summary_data, batch_flags_data):
    data_to_upsert = []
    for saddr, data in batch_summary_data.items():
        data_to_upsert.append((
            saddr,
            data['total_len'],
            data['total_payloadlen'],
            '', # flags_str will be updated later
            data['count']
        ))
    
    # 使用 UPSERT 确保批次提交时，如果 saddr 已存在，则更新值
    cursor.executemany('''
        INSERT INTO packet_summary (saddr, total_len, total_payloadlen, flags_str, packet_count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(saddr) DO UPDATE SET
            total_len = total_len + excluded.total_len,
            total_payloadlen = total_payloadlen + excluded.total_payloadlen,
            packet_count = packet_count + excluded.packet_count;
    ''', data_to_upsert)

    flags_to_insert = []
    for saddr, flags_set in batch_flags_data.items():
        for flag in flags_set:
            flags_to_insert.append((saddr, flag))
    
    # 插入或忽略新的 flag_value，避免重复
    cursor.executemany('''
        INSERT OR IGNORE INTO saddr_flags (saddr, flag_value)
        VALUES (?, ?);
    ''', flags_to_insert)

    # 更新 packet_summary 中的 flags_str
    for saddr in batch_summary_data.keys():
        cursor.execute('''
            SELECT GROUP_CONCAT(flag_value)
            FROM (
                SELECT flag_value
                FROM saddr_flags
                WHERE saddr = ?
                ORDER BY flag_value
            );
        ''', (saddr,))
        flags_str = cursor.fetchone()[0] # GROUP_CONCAT 返回的是一个字符串，fetchone()[0] 获取它
        cursor.execute('''
            UPDATE packet_summary
            SET flags_str = ?
            WHERE saddr = ?;
        ''', (flags_str, saddr))

    conn.commit()

def _convert_db_row_to_dict(row):
    return {
        'saddr': row[0],
        'len': row[1],
        'payloadlen': row[2],
        'flags': row[3],
        'count': row[4]
    }

if __name__ == "__main__":
    input_csv = "eg_SYN_PSH.csv"
    output_csv = "egro_SYN_PSH.csv"
    limit_count = None # 默认为 None，表示为 'all' (不限制)
    length_threshold = 1000 # 默认为 1000

    # 命令行参数解析：
    # python script.py input_file output_file
    # python script.py input_file output_file limit_count
    # python script.py input_file output_file limit_count length_threshold
    
    if len(sys.argv) == 5: # input, output, limit_count, length_threshold
        input_csv = sys.argv[1]
        output_csv = sys.argv[2]
        try:
            limit_val = int(sys.argv[3])
            if limit_val < 0:
                print("Error: limit_count cannot be negative. Setting to 0 (unlimited).")
                limit_count = 0
            else:
                limit_count = limit_val
        except ValueError:
            print("Warning: limit_count must be an integer. Ignoring limit.")
            limit_count = None # 保持无限制
        
        try:
            threshold_val = int(sys.argv[4])
            if threshold_val < 0:
                print("Error: length_threshold cannot be negative. Setting to 0.")
                length_threshold = 0
            else:
                length_threshold = threshold_val
        except ValueError:
            print("Warning: length_threshold must be an integer. Using default 1000.")
            length_threshold = 1000 # 使用默认值
            
    elif len(sys.argv) == 4: # input, output, limit_count
        input_csv = sys.argv[1]
        output_csv = sys.argv[2]
        try:
            limit_val = int(sys.argv[3])
            if limit_val < 0:
                print("Error: limit_count cannot be negative. Setting to 0 (unlimited).")
                limit_count = 0
            else:
                limit_count = limit_val
        except ValueError:
            print("Warning: limit_count must be an integer. Ignoring limit.")
            limit_count = None # 保持无限制
        # length_threshold 保持默认值 1000
    elif len(sys.argv) == 3: # input, output
        input_csv = sys.argv[1]
        output_csv = sys.argv[2]
        # limit_count 保持默认 None
        # length_threshold 保持默认 1000
    elif len(sys.argv) != 1:
        print(f"Usage: python {sys.argv[0]} [input_csv] [output_csv] [optional_limit_count] [optional_length_threshold]")
        sys.exit(1)
    
    process_csv_optimized(input_csv, output_csv, limit_count, length_threshold)
    print(f"Processing finished, results saved in {output_csv}")
