"""配置常量与协议枚举。

这些常量在重构前位于 ``app.py`` 的第 52-181 行。拆分后由 :mod:`pressure.state`
与 :mod:`pressure.routes` 等模块共享，保持语义与默认值完全一致。
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TestMethod(Enum):
    """协议测试方法枚举。"""

    MEMCACHED = "memcached"
    DNS = "dns"
    NTP = "ntp"
    TCP = "tcp"
    MULTI = "multi"


class TestStatus(Enum):
    """测试运行状态枚举。"""

    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class TestConfig:
    """单次压力测试的配置。"""

    target_ip: str
    target_port: int = 80
    method: str = "single"  # single 或 multi
    single_method: Optional[TestMethod] = None
    multi_protocols: List[str] = field(
        default_factory=lambda: ["memcached", "dns", "ntp"]
    )
    duration_minutes: int = 5
    threads: int = 8
    data_size_kb: int = 300
    target_pps: int = 5000
    tcp_pkt_methods: List[str] = field(default_factory=list)
    protocol_sources: Dict[str, List[str]] = field(default_factory=dict)
    # TCP TTL，论文推荐 255 利用路由环路放大
    ttl: int = 255


@dataclass
class TestStats:
    """测试过程中的累计统计量。"""

    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float = 0
    end_time: float = 0
    current_pps: float = 0
    current_mbps: float = 0
    status: TestStatus = TestStatus.IDLE
    error_message: str = ""
    progress_percent: float = 0
    victim_mbps: float = 0.0
    max_amplification_factor: float = 0.0
    expected_amplification: float = 0.0
    protocol_details: Dict[str, Any] = field(default_factory=dict)
    selected_protocols: List[str] = field(default_factory=list)


# 合法服务器协议集合（与 ``list_protocol_local_resources`` 的枚举保持一致）
VALID_SERVER_PROTOCOLS = {"tcp", "memcached", "dns", "ntp"}

# GEOIP 本地缓存与数据库路径
GEOIP_CACHE_FILE = os.path.join("config", "geoip_cache.json")
GEOIP_LOCAL_DB_FILE = os.path.join(
    "attack_resources", "tcp", "resources", "geoip", "GeoLite2-City.mmdb"
)
GEOIP_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
GEOIP_BATCH_SIZE = 100

# 资源根目录，供各协议扫描模块与 API 使用
ATTACK_RESOURCES_ROOT = os.path.join("attack_resources")

# 这些国家支持在地理聚合时进一步落到“省/州”一级
SUBDIVISION_COUNTRY_CODES = {"CN", "US", "RU", "CA", "AU", "BR", "IN"}

# 中国特区 / 台湾的中英文别名归一化表
CHINA_AREA_ALIASES = {
    "HK": ("HK", "Hong Kong"),
    "HKG": ("HK", "Hong Kong"),
    "HONG KONG": ("HK", "Hong Kong"),
    "HONG KONG SAR": ("HK", "Hong Kong"),
    "MO": ("MO", "Macao"),
    "MAC": ("MO", "Macao"),
    "MACAO": ("MO", "Macao"),
    "MACAU": ("MO", "Macao"),
    "MACAO SAR": ("MO", "Macao"),
    "TW": ("TW", "Taiwan"),
    "TWN": ("TW", "Taiwan"),
    "TAIWAN": ("TW", "Taiwan"),
}

# 常见国家英文/别名到 ISO 两位代码的映射
COUNTRY_NAME_TO_CODE = {
    "ARGENTINA": "AR",
    "AUSTRALIA": "AU",
    "AZERBAIJAN": "AZ",
    "BANGLADESH": "BD",
    "BRAZIL": "BR",
    "CANADA": "CA",
    "CHINA": "CN",
    "COLOMBIA": "CO",
    "CROATIA": "HR",
    "CZECHIA": "CZ",
    "ECUADOR": "EC",
    "FRANCE": "FR",
    "GERMANY": "DE",
    "HUNGARY": "HU",
    "INDIA": "IN",
    "INDONESIA": "ID",
    "IRAN": "IR",
    "JAPAN": "JP",
    "KENYA": "KE",
    "LEBANON": "LB",
    "MALI": "ML",
    "MEXICO": "MX",
    "PAKISTAN": "PK",
    "PERU": "PE",
    "POLAND": "PL",
    "PORTUGAL": "PT",
    "ROMANIA": "RO",
    "RUSSIA": "RU",
    "SAUDI ARABIA": "SA",
    "SINGAPORE": "SG",
    "SOUTH AFRICA": "ZA",
    "SOUTH KOREA": "KR",
    "SPAIN": "ES",
    "TAJIKISTAN": "TJ",
    "THAILAND": "TH",
    "TUNISIA": "TN",
    "UKRAINE": "UA",
    "UNITED KINGDOM": "GB",
    "UNITED STATES": "US",
    "UNITED STATES OF AMERICA": "US",
    "VIETNAM": "VN",
}
