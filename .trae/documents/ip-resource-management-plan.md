# IP资源管理与TCP结果处理完善方案

## 一、需求分析

### 1.1 核心需求

| 序号 | 需求点 | 说明 | 现状分析 |
|------|--------|------|----------|
| 1 | 自动爬取IP资源 | TCP可爬取ipdeny.com，UDP资源可爬取Shodan/Fofa等 | 无自动爬取功能 |
| 2 | IP资源管理方案 | 同时支持手动txt和自动获取的IP资源 | 仅支持手动txt文件 |
| 3 | 前端资源文件编辑 | 在前端对已有的txt进行修改与新增 | 无此功能 |
| 4 | 更多IP源网站 | 搜寻提供原始IP段的网站 | 需调研 |
| 5 | TCP优质IP筛选 | 类似DNS输出qualified_ips.txt | 只有分析报告，无优质IP文件 |

### 1.2 用户关切点

| 关切点 | 说明 | 解决方案 |
|--------|------|----------|
| 爬取结果怎么存取 | 如何存储爬取的IP数据 | 结构化存储，包含元数据（来源、国家、时间等） |
| 区分爬取来源 | 知道IP来自哪个网站 | 目录结构+文件命名+元数据文件 |
| 区分国家/地区 | 知道IP属于哪个国家 | 目录按国家组织，文件命名包含国家代码 |
| 爬取结果管理 | 如何管理大量爬取结果 | 分类目录结构+元数据索引+过期清理 |
| 资源选择不混乱 | 在"IP资源"下拉框选择时不混乱 | 前端分类展示，按类型/来源/国家分组 |

---

## 二、架构设计

### 2.1 IP资源管理系统架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     IP资源管理系统                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐        ┌──────────────┐        ┌──────────────────┐   │
│  │   手动资源库  │        │   自动资源库  │        │    资源元数据     │   │
│  │              │        │              │        │                  │   │
│  │ manual/      │        │ auto/        │        │ resources.db     │   │
│  │   custom.txt │        │   ipdeny/    │        │ (SQLite索引)     │   │
│  │   mylist.txt │        │     cn.txt   │        │                  │   │
│  │              │        │     us.txt   │        │ - 来源           │   │
│  │              │        │   shodan/    │        │ - 国家           │   │
│  │              │        │     memcached.txt  │   │ - 时间           │   │
│  │              │        │     dns.txt   │        │ - IP数量         │   │
│  │              │        │   fofa/      │        │ - 类型           │   │
│  │              │        │     ntp.txt   │        │                  │   │
│  └──────┬───────┘        └──────┬───────┘        └────────┬─────────┘   │
│         │                       │                         │             │
│         └──────────┬────────────┘                         │             │
│                    ▼                                      │             │
│         ┌──────────────────┐                              │             │
│         │    资源索引器     │◄─────────────────────────────┘             │
│         │                  │                                         │
│         │ - 扫描目录结构    │                                         │
│         │ - 读取元数据      │                                         │
│         │ - 构建索引        │                                         │
│         │ - 提供统一列表    │                                         │
│         └────────┬─────────┘                                         │
│                  │                                                  │
│                  ▼                                                  │
│         ┌──────────────────┐                                        │
│         │   资源选择接口    │                                        │
│         │  (前端下拉框)     │                                        │
│         │                  │                                        │
│         │ - 按类型分组      │                                        │
│         │ - 按来源分组      │                                        │
│         │ - 按国家分组      │                                        │
│         │ - 搜索过滤        │                                        │
│         └──────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 资源目录结构设计

```
attack_resources/shared/ip_lists/
├── manual/                          # 手动资源 - 用户创建和编辑
│   ├── custom.txt                   # 用户自定义IP列表
│   ├── china_censors.txt            # 用户收集的中国审查IP
│   └── ...
├── auto/                            # 自动资源 - 爬虫获取
│   ├── ipdeny/                      # IPdeny网站爬取
│   │   ├── cn_20240115.txt          # 中国IP段 (日期戳)
│   │   ├── us_20240115.txt          # 美国IP段
│   │   ├── ru_20240115.txt          # 俄罗斯IP段
│   │   └── metadata.json            # 该目录元数据
│   ├── shodan/                      # Shodan API爬取
│   │   ├── memcached_20240115.txt   # Memcached服务IP
│   │   ├── dns_20240115.txt         # DNS服务器IP
│   │   └── metadata.json
│   ├── fofa/                        # FOFA API爬取
│   │   ├── ntp_20240115.txt         # NTP服务器IP
│   │   └── metadata.json
│   └── maxmind/                     # MaxMind数据导出
│       ├── cn_geoip.txt
│       └── metadata.json
└── metadata/                        # 全局元数据
    └── resources.db                 # SQLite索引数据库
```

### 2.3 元数据文件格式

每个自动资源目录下的`metadata.json`：

```json
{
  "source": "ipdeny",
  "source_url": "https://www.ipdeny.com/ipblocks/",
  "country": "cn",
  "country_name": "中国",
  "protocol": "tcp",
  "ip_count": 15000,
  "fetch_time": "2024-01-15T10:30:00",
  "update_interval_hours": 24,
  "next_update_time": "2024-01-16T10:30:00"
}
```

### 2.4 资源类型定义

| 资源类型 | 来源 | 存储位置 | 命名规范 | 特点 |
|----------|------|----------|----------|------|
| 手动资源 | 用户上传/编辑 | `shared/ip_lists/manual/*.txt` | `{自定义名称}.txt` | 用户可控，格式灵活 |
| 自动资源-IPdeny | IPdeny网站爬取 | `shared/ip_lists/auto/ipdeny/{country}_{date}.txt` | `{国家代码}_{日期}.txt` | 按国家分类，日期戳管理 |
| 自动资源-Shodan | Shodan API | `shared/ip_lists/auto/shodan/{protocol}_{date}.txt` | `{协议}_{日期}.txt` | 按协议分类 |
| 自动资源-FOFA | FOFA API | `shared/ip_lists/auto/fofa/{protocol}_{date}.txt` | `{协议}_{日期}.txt` | 按协议分类 |
| 自动资源-MaxMind | MaxMind数据库 | `shared/ip_lists/auto/maxmind/{country}_{date}.txt` | `{国家代码}_{日期}.txt` | 按国家分类 |

---

## 三、爬虫数据源调研

### 3.1 TCP资源（IP段/IP列表）

| 网站 | 网址 | 内容类型 | 使用方式 | 国家区分 |
|------|------|----------|----------|----------|
| IPdeny | https://www.ipdeny.com/ipblocks/ | 国家/地区IP段(CIDR) | 爬取HTML页面提取 | ✅ 按国家代码分文件 |
| IP2Location | https://www.ip2location.com/free/visitor-ip | IP地理信息 | API获取 | ✅ 响应中包含国家 |
| MaxMind | https://dev.maxmind.com/geoip/geoip2/free-downloadable-databases | GeoIP数据库 | 下载mmdb解析 | ✅ 按国家导出 |
| IPinfo | https://ipinfo.io/ | IP信息查询 | API获取 | ✅ 响应中包含国家 |
| IPAPI | https://ipapi.co/ | IP地理信息 | 免费API | ✅ 响应中包含国家 |

### 3.2 UDP放大攻击资源

| 网站 | 网址 | 内容类型 | 使用方式 | 协议区分 |
|------|------|----------|----------|----------|
| Shodan | https://www.shodan.io/ | 设备搜索 | API搜索特定服务 | ✅ 按端口/协议搜索 |
| FOFA | https://fofa.info/ | 设备搜索 | API搜索特定服务 | ✅ 按端口/协议搜索 |
| Censys | https://censys.io/ | 设备搜索 | API搜索特定服务 | ✅ 按端口/协议搜索 |
| ZoomEye | https://www.zoomeye.org/ | 设备搜索 | API搜索特定服务 | ✅ 按端口/协议搜索 |

---

## 四、实施步骤

### 4.1 第一步：创建统一IP资源管理模块

**目标**：建立IP资源管理系统，支持手动和自动两种资源来源，包含元数据管理

**文件变更**：

| 文件 | 操作 | 说明 |
|------|------|------|
| `attack_resources/shared/ip_resource_manager.py` | 新建 | IP资源管理器，统一管理手动和自动资源 |
| `attack_resources/shared/spiders/__init__.py` | 新建 | 爬虫模块初始化 |
| `attack_resources/shared/spiders/ipdeny_spider.py` | 新建 | IPdeny网站爬虫，获取国家IP段 |
| `attack_resources/shared/spiders/shodan_spider.py` | 新建 | Shodan API爬虫框架 |
| `attack_resources/shared/spiders/fofa_spider.py` | 新建 | FOFA API爬虫框架 |
| `attack_resources/shared/config.py` | 新建 | 爬虫配置管理 |

**核心功能**：

| 函数 | 功能 |
|------|------|
| `list_resources(filter_type=None, filter_source=None, filter_country=None)` | 获取资源列表，支持多维度过滤 |
| `read_resource(filename)` | 读取资源文件内容 |
| `write_resource(filename, content)` | 写入/更新资源文件 |
| `create_resource(filename, content, metadata=None)` | 创建新资源文件（可附带元数据） |
| `delete_resource(filename)` | 删除资源文件 |
| `fetch_auto_resources(spider_name, params)` | 执行爬虫获取资源 |
| `get_resource_metadata(filename)` | 获取资源文件的元数据 |
| `update_resource_metadata(filename, metadata)` | 更新资源文件的元数据 |

### 4.2 第二步：扩展API接口

**目标**：为资源管理提供REST API支持，包含多维度筛选和元数据管理

**文件变更**：

| 文件 | 操作 | 说明 |
|------|------|------|
| `attack_resources/shared/attack_resource_api.py` | 修改 | 添加IP资源管理API |

**新增API端点**：

| 端点 | 方法 | 功能 | 参数 |
|------|------|------|------|
| `/api/attack-resource/resources` | GET | 列出所有可用IP资源文件 | `type`, `source`, `country`, `protocol` |
| `/api/attack-resource/resources/<filename>` | GET | 读取资源文件内容 | - |
| `/api/attack-resource/resources/<filename>` | PUT | 更新资源文件内容 | `content`, `metadata` |
| `/api/attack-resource/resources/<filename>` | POST | 创建新资源文件 | `content`, `metadata` |
| `/api/attack-resource/resources/<filename>` | DELETE | 删除资源文件 | - |
| `/api/attack-resource/resources/fetch` | POST | 执行爬虫获取自动资源 | `spider`, `params` |
| `/api/attack-resource/resources/metadata/<filename>` | GET | 获取资源元数据 | - |
| `/api/attack-resource/resources/sources` | GET | 获取可用的爬取来源列表 | - |
| `/api/attack-resource/resources/countries` | GET | 获取可用的国家列表 | - |

**API返回示例**：

```json
{
  "success": true,
  "resources": [
    {
      "name": "cn_20240115.txt",
      "filename": "cn_20240115.txt",
      "path": "auto/ipdeny/cn_20240115.txt",
      "type": "auto",
      "source": "ipdeny",
      "country": "cn",
      "country_name": "中国",
      "protocol": "tcp",
      "ip_count": 15000,
      "fetch_time": "2024-01-15T10:30:00",
      "size_bytes": 125000,
      "non_empty_lines": 15000
    },
    {
      "name": "custom.txt",
      "filename": "custom.txt",
      "path": "manual/custom.txt",
      "type": "manual",
      "source": null,
      "country": null,
      "country_name": null,
      "protocol": null,
      "ip_count": 100,
      "fetch_time": null,
      "size_bytes": 2000,
      "non_empty_lines": 100
    }
  ],
  "filters": {
    "types": ["manual", "auto"],
    "sources": ["ipdeny", "shodan", "fofa", "maxmind"],
    "countries": ["cn", "us", "ru", "jp", "uk"]
  }
}
```

### 4.3 第三步：完善TCP结果处理

**目标**：为TCP扫描添加优质IP筛选和输出功能，与DNS/memcached/NTP保持一致

**文件变更**：

| 文件 | 操作 | 说明 |
|------|------|------|
| `attack_resources/tcp/code/tcp_censor_scan/runner.py` | 修改 | 在分析阶段后添加优质IP筛选和保存 |
| `attack_resources/shared/attack_resource_api.py` | 修改 | 在`_build_tcp_run_payload`中添加优质IP预览 |

**具体修改**：

1. 在`analyze_amplification_log()`函数后添加新阶段`extract_qualified_ips()`
2. 读取分析报告，解析放大率数据
3. 根据阈值筛选优质IP，生成`qualified_ips.txt`
4. 更新`tcp_censor_scan/resources.py`添加读取优质IP的函数
5. 在`_build_tcp_run_payload()`中添加`result_preview`字段

**TCP优质IP筛选逻辑**：

```python
def extract_qualified_ips(amplification_log_path, output_path, min_ratio=2.0):
    qualified = []
    with open(amplification_log_path) as f:
        for line in f:
            if "amplification_ratio:" in line:
                ip = _extract_ip(line)
                ratio = _extract_ratio(line)
                if ratio >= min_ratio:
                    qualified.append(ip)
    
    with open(output_path, "w") as f:
        f.write(f"# TCP优质反射器IP列表（放大率 ≥ {min_ratio}x）\n")
        f.write(f"# 生成时间: {datetime.now().isoformat()}\n")
        for ip in qualified:
            f.write(f"{ip}\n")
    
    return qualified
```

### 4.4 第四步：前端资源文件管理界面

**目标**：在前端实现IP资源文件的查看、编辑、新增和删除，分类展示不混乱

**文件变更**：

| 文件 | 操作 | 说明 |
|------|------|------|
| `templates/index.html` | 修改 | 添加资源文件管理模态框和分类选择器 |
| `static/script.js` | 修改 | 添加资源文件管理相关函数 |

**前端设计**：

#### 4.4.1 IP资源选择器（下拉框升级）

```
┌─────────────────────────────────────────────────────────────────┐
│  IP资源选择                                                    │
├─────────────────────────────────────────────────────────────────┤
│  [搜索框: 输入资源名称或国家代码]                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─ 手动资源 ───────────────────────────────────────────────┐  │
│  │  ★ custom.txt                              (100 IPs)     │  │
│  │  ★ china_censors.txt                       (500 IPs)     │  │
│  ├─ 自动资源 - IPdeny ──────────────────────────────────────┤  │
│  │  🇨🇳 中国 (cn_20240115.txt)               (15,000 IPs)    │  │
│  │  🇺🇸 美国 (us_20240115.txt)               (25,000 IPs)    │  │
│  │  🇷🇺 俄罗斯 (ru_20240115.txt)            (10,000 IPs)    │  │
│  ├─ 自动资源 - Shodan ──────────────────────────────────────┤  │
│  │  📦 Memcached (memcached_20240115.txt)    (2,000 IPs)    │  │
│  │  📦 DNS (dns_20240115.txt)               (5,000 IPs)    │  │
│  ├─ 自动资源 - FOFA ────────────────────────────────────────┤  │
│  │  📦 NTP (ntp_20240115.txt)               (3,000 IPs)    │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  [新增资源]  [编辑资源]  [删除资源]  [执行爬虫]                  │
└─────────────────────────────────────────────────────────────────┘
```

#### 4.4.2 资源文件编辑模态框

```
┌─────────────────────────────────────────────────────────────────┐
│  编辑资源文件 - custom.txt                                     │
├─────────────────────────────────────────────────────────────────┤
│  基本信息:                                                     │
│  ├─ 类型: 手动资源                                             │
│  ├─ 来源: 用户上传                                             │
│  ├─ IP数量: 100                                               │
│  └─ 创建时间: 2024-01-15 10:30                                 │
├─────────────────────────────────────────────────────────────────┤
│  内容编辑:                                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ 192.168.1.1                                              │  │
│  │ 192.168.1.2                                              │  │
│  │ 192.168.1.3                                              │  │
│  │ ...                                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  [保存]  [取消]                                                │
└─────────────────────────────────────────────────────────────────┘
```

#### 4.4.3 爬虫执行模态框

```
┌─────────────────────────────────────────────────────────────────┐
│  执行爬虫获取资源                                               │
├─────────────────────────────────────────────────────────────────┤
│  选择爬虫:                                                     │
│  ├─ ○ IPdeny (获取国家IP段)                                   │
│  ├─ ○ Shodan (搜索设备服务)                                   │
│  └─ ○ FOFA (搜索设备服务)                                      │
├─────────────────────────────────────────────────────────────────┤
│  参数配置:                                                     │
│  ├─ 国家选择: [🇨🇳中国] [🇺🇸美国] [🇷🇺俄罗斯] [🇯🇵日本]        │
│  ├─ 协议选择: [TCP] [DNS] [Memcached] [NTP]                   │
│  └─ 获取数量: [1000] IP                                        │
├─────────────────────────────────────────────────────────────────┤
│  [开始爬取]  [取消]                                            │
└─────────────────────────────────────────────────────────────────┘
```

### 4.5 第五步：爬虫实现与配置

**目标**：实现具体的爬虫模块，支持自动获取IP资源，包含元数据记录

**文件变更**：

| 文件 | 操作 | 说明 |
|------|------|------|
| `attack_resources/shared/spiders/ipdeny_spider.py` | 新建 | IPdeny爬虫实现 |
| `attack_resources/shared/spiders/__init__.py` | 修改 | 注册爬虫 |
| `attack_resources/shared/config.py` | 新建 | 爬虫配置管理 |

**爬虫配置示例**：

```python
SPIDER_CONFIG = {
    "ipdeny": {
        "enabled": True,
        "base_url": "https://www.ipdeny.com/ipblocks/",
        "target_countries": {
            "cn": "中国",
            "ru": "俄罗斯",
            "us": "美国",
            "jp": "日本",
            "uk": "英国",
        },
        "update_interval_hours": 24,
    },
    "shodan": {
        "enabled": False,
        "api_key": "",
        "queries": {
            "memcached": {"query": "port:11211", "protocol": "memcached"},
            "dns": {"query": "port:53 AND recursion:enabled", "protocol": "dns"},
            "ntp": {"query": "port:123", "protocol": "ntp"},
        },
        "limit_per_query": 1000,
    },
    "fofa": {
        "enabled": False,
        "email": "",
        "key": "",
        "queries": {
            "memcached": {"query": "protocol=\"memcached\"", "protocol": "memcached"},
            "dns": {"query": "protocol=\"dns\"", "protocol": "dns"},
            "ntp": {"query": "protocol=\"ntp\"", "protocol": "ntp"},
        },
        "limit_per_query": 1000,
    },
}
```

**IPdeny爬虫实现要点**：

```python
def fetch_ipdeny(country_code, country_name):
    url = f"https://www.ipdeny.com/ipblocks/data/countries/{country_code}.zone"
    response = requests.get(url)
    
    ips = []
    for line in response.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)  # CIDR格式或单个IP
    
    timestamp = datetime.now().strftime("%Y%m%d")
    filename = f"{country_code}_{timestamp}.txt"
    filepath = f"auto/ipdeny/{filename}"
    
    # 保存IP文件
    with open(filepath, "w") as f:
        for ip in ips:
            f.write(f"{ip}\n")
    
    # 保存元数据
    metadata = {
        "source": "ipdeny",
        "source_url": url,
        "country": country_code,
        "country_name": country_name,
        "protocol": "tcp",
        "ip_count": len(ips),
        "fetch_time": datetime.now().isoformat(),
        "update_interval_hours": 24,
    }
    with open("auto/ipdeny/metadata.json", "w") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    
    return {"filename": filename, "ip_count": len(ips)}
```

---

## 五、资源管理流程

### 5.1 爬虫获取流程

```
用户发起爬取请求
    │
    ▼
选择爬虫类型 (IPdeny/Shodan/FOFA)
    │
    ▼
配置爬取参数 (国家/协议/数量)
    │
    ▼
执行爬虫获取IP数据
    │
    ▼
按目录结构保存文件
    ├─ auto/ipdeny/cn_20240115.txt
    ├─ auto/shodan/memcached_20240115.txt
    └─ auto/fofa/ntp_20240115.txt
    │
    ▼
生成元数据文件
    └─ auto/ipdeny/metadata.json
    │
    ▼
更新资源索引数据库
    │
    ▼
返回爬取结果给用户
```

### 5.2 资源选择流程

```
用户打开"IP资源"下拉框
    │
    ▼
前端调用API /api/attack-resource/resources
    │
    ▼
后端返回分类资源列表
    │
    ▼
前端按类型/来源/国家分组展示
    ├─ 手动资源
    ├─ 自动资源 - IPdeny (按国家)
    ├─ 自动资源 - Shodan (按协议)
    └─ 自动资源 - FOFA (按协议)
    │
    ▼
用户选择资源文件
    │
    ▼
提交扫描任务时使用选中的文件路径
```

### 5.3 资源清理流程

```
定时任务触发 (每天)
    │
    ▼
扫描auto目录下的资源文件
    │
    ▼
检查文件日期是否超过保留期限 (如7天)
    │
    ├─ 未过期 → 保留
    └─ 已过期 → 删除
    │
    ▼
更新资源索引数据库
```

---

## 六、风险与注意事项

### 6.1 风险处理

| 风险 | 风险等级 | 处理方案 |
|------|----------|----------|
| 爬虫被封禁 | 中 | 添加请求间隔、随机User-Agent、代理支持 |
| API密钥泄露 | 高 | 配置文件加入.gitignore，环境变量读取 |
| 资源文件过大 | 中 | 限制单文件最大大小，支持分页加载 |
| 网络不稳定 | 低 | 添加重试机制和超时处理 |
| 资源选择混乱 | 中 | 前端分类展示，按类型/来源/国家分组 |

### 6.2 依赖检查

需新增Python依赖：
- `requests` - HTTP请求（爬虫使用）
- `beautifulsoup4` - HTML解析（爬虫使用）
- `shodan` - Shodan API客户端（可选）
- `sqlite3` - 元数据索引（Python内置）

---

## 七、验证计划

### 7.1 功能验证

| 验证项 | 方法 | 预期结果 |
|--------|------|----------|
| 资源文件列表（分类展示） | 调用API `/api/attack-resource/resources` | 返回分类资源列表，包含类型、来源、国家信息 |
| 读取资源文件 | 调用API读取某个txt文件 | 返回文件内容和元数据 |
| 创建资源文件 | 调用API创建新txt文件 | 文件创建成功，列表更新 |
| 更新资源文件 | 调用API更新txt文件内容 | 文件内容更新 |
| 删除资源文件 | 调用API删除txt文件 | 文件删除成功，列表更新 |
| TCP优质IP输出 | 运行TCP扫描 | 生成`qualified_ips.txt`文件 |
| TCP结果预览 | 查看TCP任务详情 | 显示优质IP预览列表 |
| IPdeny爬虫 | 执行爬虫爬取中国IP | 生成`auto/ipdeny/cn_YYYYMMDD.txt`和元数据 |
| 资源分类筛选 | 前端选择按国家筛选 | 只显示对应国家的资源 |
| 资源搜索 | 前端搜索资源名称 | 显示匹配的资源 |

---

## 八、完成标准

1. ✅ 新建分支 `ip-resource-management`
2. ✅ 创建IP资源管理模块，支持手动和自动资源，包含元数据管理
3. ✅ 实现分类目录结构（manual/、auto/ipdeny/、auto/shodan/等）
4. ✅ 添加资源管理API接口，支持多维度筛选（类型、来源、国家、协议）
5. ✅ TCP扫描生成`qualified_ips.txt`文件
6. ✅ TCP任务详情展示优质IP预览
7. ✅ 前端实现资源文件编辑功能，分类展示不混乱
8. ✅ 实现IPdeny爬虫，按国家分类存储
9. ✅ 所有API测试通过
