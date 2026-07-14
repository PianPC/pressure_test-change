from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..config import SPIDER_CONFIG
from ..credential_store import get_credentials, get_cookies


class FOFASpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("fofa", {})
        self.base_url = self.config.get("base_url", "https://fofa.info")
        self.api_url = self.config.get("api_url", "https://fofa.info/api/v1/search/all")
        self.queries = self.config.get("queries", {})
        self.limit_per_query = self.config.get("limit_per_query", 1000)
        self.timeout = self.config.get("request_timeout", 30)

    def fetch(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        query_names = params.get("queries", list(self.queries.keys()))
        limit = params.get("limit", self.limit_per_query)
        output_dir = params.get("output_dir", "auto/fofa")

        creds = get_credentials("fofa") or {}
        email = creds.get("email", "")
        key = creds.get("key", "")
        cookies = get_cookies("fofa")

        # 方式一：API 密钥优先
        if email and key:
            return self._fetch_via_api(query_names, limit, output_dir, email, key)

        # 方式二/三：Cookie 网页爬取
        if cookies:
            return self._fetch_via_web(query_names, limit, output_dir, cookies)

        return {"success": False, "error": "FOFA 未配置（需 API 密钥或 Cookie，请在配置面板选择一种方式）"}

    def _fetch_via_api(self, query_names, limit, output_dir, email, key) -> Dict[str, Any]:

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
                query_b64 = base64.b64encode(query_str.encode()).decode()
                timestamp = str(int(datetime.now().timestamp()))
                sign_str = f"{email}{key}{timestamp}{query_b64}"
                sign = hashlib.md5(sign_str.encode()).hexdigest()

                url = f"{self.api_url}?email={email}&key={key}&qbase64={query_b64}&size={limit}&sign={sign}"
                response = requests.get(url, timeout=self.timeout)
                response.raise_for_status()

                data = response.json()
                ips = []

                if data.get("results"):
                    for result in data["results"]:
                        ip_str = result[0] if isinstance(result, list) else str(result)
                        if ip_str:
                            if ":" in ip_str:
                                ip_str = ip_str.split(":")[0]
                            ips.append(ip_str)

                filename = f"{query_name}_{today_str}.txt"
                output_path = base_path / output_dir / filename

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# FOFA - {protocol} servers\n")
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
                    "source_url": self.base_url,
                })

            except Exception as e:
                results.append({
                    "protocol": protocol,
                    "error": str(e),
                })

        return {
            "success": True,
            "source": "fofa",
            "source_url": self.base_url,
            "files": results,
            "total_queries": len(query_names),
            "successful": len([r for r in results if "error" not in r]),
        }

    def _fetch_via_web(self, query_names, limit, output_dir, cookies) -> Dict[str, Any]:
        """方式二/三：用浏览器 Cookie 爬取 FOFA 网页搜索结果。"""
        from bs4 import BeautifulSoup

        results = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"
        web_base = "https://fofa.info"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
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
                query_b64 = base64.b64encode(query_str.encode()).decode()
                url = f"{web_base}/result?qbase64={query_b64}"
                response = session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)

                # Cloudflare 检测
                lower_text = response.text.lower()
                if response.status_code in (403, 503) or "cf-challenge" in lower_text or "cloudflare" in lower_text:
                    results.append({
                        "protocol": protocol,
                        "error": "FOFA 被 Cloudflare 拦截，Cookie 模式可能不可用，建议使用 API 密钥",
                    })
                    continue

                # 检测登录态失效
                if "login" in lower_text or "sign in" in lower_text or response.status_code in (302, 301):
                    results.append({
                        "protocol": protocol,
                        "error": "Cookie 登录态已过期，请重新获取 Cookie",
                    })
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                ips = []
                seen = set()

                # 选择器 1: a.target（FOFA 结果页 IP 链接）
                for link in soup.select("a.target"):
                    text = link.get_text(strip=True)
                    if ip_pattern.match(text) and text not in seen:
                        seen.add(text)
                        ips.append(text)
                    href = link.get("href", "")
                    candidate = href.strip()
                    if ip_pattern.match(candidate) and candidate not in seen:
                        seen.add(candidate)
                        ips.append(candidate)

                # 选择器 2: div.r_item a, div.list_module a, div.result-item a
                if not ips:
                    for selector in ["div.r_item a", "div.list_module a", "div.result-item a"]:
                        for link in soup.select(selector):
                            text = link.get_text(strip=True)
                            if ip_pattern.match(text) and text not in seen:
                                seen.add(text)
                                ips.append(text)
                        if ips:
                            break

                # 选择器 3: span.ip
                if not ips:
                    for el in soup.select("span.ip"):
                        text = el.get_text(strip=True)
                        if ip_pattern.match(text) and text not in seen:
                            seen.add(text)
                            ips.append(text)

                # 选择器 4: 所有 a 标签文本（原逻辑兜底）
                if not ips:
                    for link in soup.find_all("a"):
                        text = link.get_text(strip=True)
                        if ip_pattern.match(text) and text not in seen:
                            seen.add(text)
                            ips.append(text)

                # 兜底：正则全文提取
                if not ips:
                    for match in ip_pattern.findall(response.text):
                        if match not in seen:
                            seen.add(match)
                            ips.append(match)

                ips = ips[:limit]

                # 0 结果时不写文件，返回 error 含调试信息
                if not ips:
                    flags = []
                    if "login" in lower_text or "sign in" in lower_text:
                        flags.append("login")
                    if "cf-challenge" in lower_text or "cloudflare" in lower_text:
                        flags.append("cloudflare")
                    if "upgrade" in lower_text or "vip" in lower_text:
                        flags.append("vip")
                    if "credits" in lower_text:
                        flags.append("credits")

                    flags_str = "、".join(flags) if flags else "无"
                    error_msg = (
                        f"网页爬取提取到 0 个 IP（status={response.status_code}, "
                        f"html_length={len(response.text)}, 含 {flags_str} 标志）。"
                        f"可能原因：Cloudflare 隐式拦截 / 网站改版 / Cookie 登录态失效 / 查询无结果。"
                        f"建议改用 API 密钥。"
                    )
                    results.append({
                        "protocol": protocol,
                        "error": error_msg,
                        "query": query_str,
                        "source_url": url,
                    })
                    continue

                filename = f"{query_name}_{today_str}.txt"
                output_path = base_path / output_dir / filename

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# FOFA - {protocol} servers\n")
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
            "source": "fofa",
            "source_url": web_base,
            "files": results,
            "total_queries": len(query_names),
            "successful": len([r for r in results if "error" not in r]),
        }

    def check_web_cookies(self, cookies: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """检查 Cookie 登录态是否有效。cookies 为 None 时从 store 读取。"""
        if cookies is None:
            cookies = get_cookies("fofa")
        if not cookies:
            return {"valid": False, "error": "Cookie 未配置"}

        try:
            session = requests.Session()
            session.cookies.update(cookies)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
            test_b64 = base64.b64encode(b"ip=1.1.1.1").decode()
            response = session.get(f"https://fofa.info/result?qbase64={test_b64}", headers=headers, timeout=self.timeout, allow_redirects=True)
            lower_text = response.text.lower()

            # Cloudflare 检测
            if response.status_code in (403, 503) or "cf-challenge" in lower_text or "cloudflare" in lower_text:
                return {"valid": False, "error": "FOFA 被 Cloudflare 拦截，Cookie 模式不可用，建议使用 API 密钥"}

            if "login" in lower_text or "sign in" in lower_text or response.status_code in (302, 301):
                return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}

            # 统计搜索结果容器
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")
            result_containers = max(
                len(soup.select("div.list_module")),
                len(soup.select("div.r_item")),
                len(soup.select("a.target")),
                len(soup.select("div.result-item")),
            )

            ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
            ip_count = len(set(ip_pattern.findall(response.text)))

            result = {"valid": True, "ip_count": ip_count, "result_containers": result_containers}
            if result_containers == 0:
                result["warning"] = "登录态有效但未找到搜索结果容器（可能是网站改版、查询无结果或 Cloudflare 隐式拦截）。"
            return result
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def check_credentials(self, credentials: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if credentials is None:
            credentials = get_credentials("fofa") or {}
        email = credentials.get("email", "")
        key = credentials.get("key", "")
        if not email or not key:
            return {"valid": False, "error": "Email or key not set"}

        try:
            test_query = base64.b64encode("ip=1.1.1.1".encode()).decode()
            timestamp = str(int(datetime.now().timestamp()))
            sign_str = f"{email}{key}{timestamp}{test_query}"
            sign = hashlib.md5(sign_str.encode()).hexdigest()

            url = f"{self.api_url}?email={email}&key={key}&qbase64={test_query}&size=1&sign={sign}"
            response = requests.get(url, timeout=self.timeout)
            data = response.json()

            if data.get("error"):
                return {"valid": False, "error": data.get("errmsg", str(data.get("error")))}
            return {"valid": True}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_available_queries(self) -> List[Dict[str, str]]:
        return [
            {"name": name, "query": info["query"], "protocol": info["protocol"]}
            for name, info in self.queries.items()
        ]