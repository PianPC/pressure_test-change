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

_COOKIE_DOMAIN = ".shodan.io"


class ShodanSpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("shodan", {})
        self.base_url = self.config.get("base_url", "https://api.shodan.io")
        self.queries = self.config.get("queries", {})
        self.limit_per_query = self.config.get("limit_per_query", 1000)
        self.timeout = self.config.get("request_timeout", 30)

    @staticmethod
    def _set_cookies_to_session(session, cookies):
        """将 cookies dict 逐个 set 到 session，带 domain。

        session.cookies.update(dict) 不设置 domain，导致 requests 发送请求时不带 cookie。
        必须用 session.cookies.set(name, value, domain=...) 逐个设置（参考 ip_collector 实现）。
        """
        for name, value in cookies.items():
            session.cookies.set(name, str(value), domain=_COOKIE_DOMAIN)

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

            except requests.HTTPError as he:
                # Shodan 返回 JSON 错误体，提取 error 字段得到具体原因
                err_msg = str(he)
                try:
                    err_data = he.response.json()
                    if isinstance(err_data, dict) and err_data.get("error"):
                        err_msg = f"{he.response.status_code} {err_data.get('error')}"
                except (ValueError, AttributeError):
                    pass
                results.append({
                    "protocol": protocol,
                    "error": err_msg,
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
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
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
                self._set_cookies_to_session(session, cookies)
                url = f"{web_base}/search?{urlencode({'query': query_str})}"
                response = session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)

                lower_text = response.text.lower()

                # 检测登录态失效（只检测重定向，不检测 login 关键词——Shodan 页面普遍含 login 字样无区分力）
                if response.status_code in (302, 301):
                    results.append({
                        "protocol": protocol,
                        "error": "Cookie 登录态已过期，请重新获取 Cookie",
                    })
                    continue

                # 检测 Cloudflare（虽然 Shodan 一般不用 CF，但防御性检测）
                if "cf-challenge" in lower_text or "cloudflare" in lower_text:
                    results.append({
                        "protocol": protocol,
                        "error": "页面被 Cloudflare 拦截",
                    })
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                ips = []
                seen = set()

                # 选择器 1: a[href^='/host/']（首选）
                for link in soup.select("a[href^='/host/']"):
                    href = link.get("href", "")
                    # /host/1.2.3.4 → 1.2.3.4
                    candidate = href.replace("/host/", "").strip()
                    if ip_pattern.match(candidate) and candidate not in seen:
                        seen.add(candidate)
                        ips.append(candidate)

                # 选择器 2: div.search-result a / div.search_result a / div.result a
                if not ips:
                    for selector in ["div.search-result a", "div.search_result a", "div.result a"]:
                        for link in soup.select(selector):
                            href = link.get("href", "")
                            # 尝试从 href 提取
                            candidate = href.replace("/host/", "").strip()
                            if ip_pattern.match(candidate) and candidate not in seen:
                                seen.add(candidate)
                                ips.append(candidate)
                            # 尝试从文本提取
                            text = link.get_text(strip=True)
                            if ip_pattern.match(text) and text not in seen:
                                seen.add(text)
                                ips.append(text)
                        if ips:
                            break

                # 选择器 3: [data-ip] 属性
                if not ips:
                    for el in soup.select("[data-ip]"):
                        candidate = el.get("data-ip", "").strip()
                        if ip_pattern.match(candidate) and candidate not in seen:
                            seen.add(candidate)
                            ips.append(candidate)

                # 选择器 4: 直接从结果容器文本提取 IP
                if not ips:
                    for container_selector in ["div.search-result", "div.search_result", "div.result"]:
                        for container in soup.select(container_selector):
                            text = container.get_text(" ", strip=True)
                            for match in ip_pattern.findall(text):
                                if match not in seen:
                                    seen.add(match)
                                    ips.append(match)
                        if ips:
                            break

                # 兜底：正则全文提取
                if not ips:
                    for match in ip_pattern.findall(response.text):
                        if match not in seen:
                            seen.add(match)
                            ips.append(match)

                ips = ips[:limit]

                # 0 结果时不写文件，返回 error 含调试信息
                if not ips:
                    # 检测标志位
                    flags = []
                    # 注：不再检测 "login" 关键词，Shodan 页面普遍含 login 字样无区分力
                    if "cf-challenge" in lower_text or "cloudflare" in lower_text:
                        flags.append("cloudflare")
                    if "upgrade" in lower_text or "subscription" in lower_text:
                        flags.append("subscription")
                    if "query credits" in lower_text or "credits" in lower_text:
                        flags.append("credits")

                    flags_str = "、".join(flags) if flags else "无"
                    error_msg = (
                        f"网页爬取提取到 0 个 IP（status={response.status_code}, "
                        f"html_length={len(response.text)}, 含 {flags_str} 标志）。"
                        f"可能原因：免费账号搜索受限 / 网站改版 / Cookie 登录态失效。"
                        f"建议改用 API 密钥或检查 Cookie。"
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
            self._set_cookies_to_session(session, cookies)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            }
            response = session.get("https://www.shodan.io/search?query=port:53", headers=headers, timeout=self.timeout, allow_redirects=True)
            lower_text = response.text.lower()
            # 只检测重定向（Shodan 未登录会 302 到 /account/login）；不检测 login 关键词（无区分力）
            if response.status_code in (302, 301):
                return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}

            # 统计搜索结果容器数量（侧边栏推荐 IP 不计入）
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")
            result_containers = max(
                len(soup.select("div.search-result")),
                len(soup.select("div.search_result")),
                len(soup.select("div.result")),
                len(soup.select("[data-ip]")),
                len(soup.select("a[href^='/host/']")),
            )

            # 统计页面中的 IP 数量作为可用性指标
            ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
            ip_count = len(set(ip_pattern.findall(response.text)))

            # 检测免费账号限制标志
            limited = any(kw in lower_text for kw in ["upgrade", "subscription", "query credits", "credits"])

            result = {
                "valid": True,
                "ip_count": ip_count,
                "result_containers": result_containers,
            }

            if result_containers == 0:
                if limited:
                    result["warning"] = "登录态有效但搜索结果为空，可能是免费账号受限。Shodan 免费账号网页搜索也受 query credits 限制，建议购买订阅或改用其他数据源。"
                else:
                    result["warning"] = "登录态有效但未找到搜索结果容器（可能是网站改版或查询无结果）。"

            return result
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
            query_credits = data.get("query_credits", 0)
            scan_credits = data.get("scan_credits", 0)
            plan = data.get("plan", "")
            result = {
                "valid": True,
                "user": data.get("email", ""),
                "query_credits": query_credits,
                "scan_credits": scan_credits,
                "plan": plan,
            }
            if query_credits <= 0:
                result["warning"] = f"API 有效但无搜索额度（query_credits=0）。免费账号通常无法使用搜索 API，需购买付费 plan 或改用 Cookie 模式。"
            return result
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_available_queries(self) -> List[Dict[str, str]]:
        return [
            {"name": name, "query": info["query"], "protocol": info["protocol"]}
            for name, info in self.queries.items()
        ]