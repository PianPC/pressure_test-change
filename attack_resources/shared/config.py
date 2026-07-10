from __future__ import annotations

SPIDER_CONFIG = {
    "ipdeny": {
        "enabled": True,
        "base_url": "https://www.ipdeny.com/ipblocks/",
        "data_url": "https://www.ipdeny.com/ipblocks/data/countries/",
        "target_countries": {
            "cn": "中国",
            "ru": "俄罗斯",
            "us": "美国",
            "jp": "日本",
            "uk": "英国",
            "de": "德国",
            "fr": "法国",
            "ca": "加拿大",
            "au": "澳大利亚",
            "br": "巴西",
            "kr": "韩国",
            "in": "印度",
            "it": "意大利",
            "es": "西班牙",
            "nl": "荷兰",
        },
        "update_interval_hours": 24,
        "request_timeout": 30,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    },
    "shodan": {
        "enabled": False,
        "api_key": "",
        "base_url": "https://api.shodan.io",
        "queries": {
            "memcached": {"query": "port:11211", "protocol": "memcached"},
            "dns": {"query": "port:53 AND recursion:enabled", "protocol": "dns"},
            "ntp": {"query": "port:123", "protocol": "ntp"},
            "snmp": {"query": "port:161", "protocol": "snmp"},
            "ssdp": {"query": "port:1900", "protocol": "ssdp"},
            "ldap": {"query": "port:389", "protocol": "ldap"},
        },
        "limit_per_query": 1000,
        "update_interval_hours": 24,
        "request_timeout": 30,
    },
    "fofa": {
        "enabled": False,
        "email": "",
        "key": "",
        "base_url": "https://fofa.info",
        "api_url": "https://fofa.info/api/v1/search/all",
        "queries": {
            "memcached": {"query": 'protocol="memcached"', "protocol": "memcached"},
            "dns": {"query": 'protocol="dns"', "protocol": "dns"},
            "ntp": {"query": 'protocol="ntp"', "protocol": "ntp"},
            "snmp": {"query": 'protocol="snmp"', "protocol": "snmp"},
            "ssdp": {"query": 'protocol="ssdp"', "protocol": "ssdp"},
        },
        "limit_per_query": 1000,
        "update_interval_hours": 24,
        "request_timeout": 30,
    },
    "maxmind": {
        "enabled": False,
        "download_url": "https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz",
        "update_interval_hours": 168,
    },
}

RESOURCE_SETTINGS = {
    "auto_cleanup_days": 7,
    "max_file_size_mb": 50,
    "max_lines_per_file": 1000000,
}