from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from ..config import SPIDER_CONFIG
from ..credential_store import get_credentials, get_cookies


class ShodanSpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("shodan", {})
        self.base_url = self.config.get("base_url", "https://api.shodan.io")
        self.queries = self.config.get("queries", {})
        self.limit_per_query = self.config.get("limit_per_query", 1000)
        self.timeout = self.config.get("request_timeout", 30)

    def fetch(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        query_names = params.get("queries", list(self.queries.keys()))
        limit = params.get("limit", self.limit_per_query)
        output_dir = params.get("output_dir", "auto/shodan")

        creds = get_credentials("shodan") or {}
        api_key = creds.get("api_key", "")
        cookies = get_cookies("shodan")

        # 方式一：API 密钥优先
        if api_key:
            return self._fetch_via_api(query_names, limit, output_dir, api_key)

        # 方式二/三：Cookie 网页爬取
        if cookies:
            return self._fetch_via_web(query_names, limit, output_dir, cookies)

        return {"success": False, "error": "Shodan 未配置（需 API 密钥或 Cookie，请在配置面板选择一种方式）"}

    def _fetch_via_api(self, query_names, limit, output_dir, api_key) -> Dict[str, Any]:

        results = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"

        for query_name in query_names:
            if query_name not in self.queries:
                continue

            query_info = self.queries[query_name]
            query_str = query_info["query"]
            protocol = query_info["protocol"]

            try:
                url = f"{self.base_url}/shodan/host/search"
                response = requests.get(
                    url,
                    params={"key": api_key, "query": query_str, "limit": limit},
                    timeout=self.timeout,
                )
                response.raise_for_status()

                data = response.json()
                ips = []

                for match in data.get("matches", []):
                    ip_str = match.get("ip_str")
                    if ip_str:
                        port = match.get("port", "")
                        org = match.get("org", "")
                        location = match.get("location", {})
                        country_code = location.get("country_code", "")
                        country_name = location.get("country_name", "")

                        line = ip_str
                        if org:
                            line += f", org={org}"
                        if country_code:
                            line += f", country={country_code}"
                        ips.append(line)

                filename = f"{query_name}_{today_str}.txt"
                output_path = base_path / output_dir / filename

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# Shodan - {protocol} servers\n")
                    f.write(f"# Query: {query_str}\n")
                    f.write(f"# Fetch time: {datetime.now().isoformat()}\n")
                    f.write(f"# Total results: {len(ips)}\n")
                    for ip in ips:
                        f.write(f"{ip}\n")

                results.append({
                    "path": f"{output_dir}/{filename}",
                    "protocol": protocol,
                    "ip_count": len(ips),
                    "query": query_str,
                    "source_url": url,
                })

            except Exception as e:
                results.append({
                    "protocol": protocol,
                    "error": str(e),
                })

        return {
            "success": True,
            "source": "shodan",
            "source_url": self.base_url,
            "files": results,
            "total_queries": len(query_names),
            "successful": len([r for r in results if "error" not in r]),
        }

    def _fetch_via_web(self, query_names, limit, output_dir, cookies) -> Dict[str, Any]:
        """方式二/三：用浏览器 Cookie 爬取 Shodan 网页搜索结果。"""
        from bs4 import BeautifulSoup

        results = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"
        web_base = "https://www.shodan.io"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }
        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

        for query_name in query_names:
            if query_name not in self.queries:
                continue

            query_info = self.queries[query_name]
            query_str = query_info["query"]
            protocol = query_info["protocol"]

            try:
                session = requests.Session()
                session.cookies.update(cookies)
                url = f"{web_base}/search?{urlencode({'query': query_str})}"
                response = session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)

                # 检测登录态失效
                lower_text = response.text.lower()
                if response.status_code in (302, 301) or "login" in lower_text or "sign in" in lower_text:
                    results.append({
                        "protocol": protocol,
                        "error": "Cookie 登录态已过期，请重新获取 Cookie",
                    })
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                ips = []
                seen = set()

                # 优先从搜索结果容器提取
                for link in soup.select("a[href^='/host/']"):
                    href = link.get("href", "")
                    # /host/1.2.3.4 → 1.2.3.4
                    candidate = href.replace("/host/", "").strip()
                    if ip_pattern.match(candidate) and candidate not in seen:
                        seen.add(candidate)
                        ips.append(candidate)

                # 兜底：正则全文提取
                if not ips:
                    for match in ip_pattern.findall(response.text):
                        if match not in seen:
                            seen.add(match)
                            ips.append(match)

                ips = ips[:limit]

                filename = f"{query_name}_{today_str}.txt"
                output_path = base_path / output_dir / filename

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# Shodan - {protocol} servers\n")
                    f.write(f"# Query: {query_str}\n")
                    f.write(f"# Mode: web-cookie\n")
                    f.write(f"# Fetch time: {datetime.now().isoformat()}\n")
                    f.write(f"# Total results: {len(ips)}\n")
                    for ip in ips:
                        f.write(f"{ip}\n")

                results.append({
                    "path": f"{output_dir}/{filename}",
                    "protocol": protocol,
                    "ip_count": len(ips),
                    "query": query_str,
                    "source_url": url,
                })

            except Exception as e:
                results.append({
                    "protocol": protocol,
                    "error": str(e),
                })

        return {
            "success": True,
            "source": "shodan",
            "source_url": web_base,
            "files": results,
            "total_queries": len(query_names),
            "successful": len([r for r in results if "error" not in r]),
        }

    def check_web_cookies(self, cookies: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """检查 Cookie 登录态是否有效。cookies 为 None 时从 store 读取。"""
        if cookies is None:
            cookies = get_cookies("shodan")
        if not cookies:
            return {"valid": False, "error": "Cookie 未配置"}

        try:
            session = requests.Session()
            session.cookies.update(cookies)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
            response = session.get("https://www.shodan.io/search?query=port:53", headers=headers, timeout=self.timeout, allow_redirects=True)
            lower_text = response.text.lower()
            if response.status_code in (302, 301) or "login" in lower_text or "sign in" in lower_text:
                return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}

            # 统计页面中的 IP 数量作为可用性指标
            ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
            ip_count = len(set(ip_pattern.findall(response.text)))
            return {"valid": True, "ip_count": ip_count}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def check_api_key(self, credentials: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if credentials is None:
            credentials = get_credentials("shodan") or {}
        api_key = credentials.get("api_key", "")
        if not api_key:
            return {"valid": False, "error": "API key not set"}

        try:
            url = f"{self.base_url}/account/profile"
            response = requests.get(url, params={"key": api_key}, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return {"valid": True, "user": data.get("email", "")}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_available_queries(self) -> List[Dict[str, str]]:
        return [
            {"name": name, "query": info["query"], "protocol": info["protocol"]}
            for name, info in self.queries.items()
        ]