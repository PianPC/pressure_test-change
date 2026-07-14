from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..config import SPIDER_CONFIG
from ..credential_store import get_credentials, get_cookies


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


class FOFASpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("fofa", {})
        self.base_url = self.config.get("base_url", "https://fofa.info")
        self.api_url = self.config.get("api_url", "https://fofa.info/api/v1/search/all")
        self.queries = self.config.get("queries", {})
        self.limit_per_query = self.config.get("limit_per_query", 1000)
        self.timeout = self.config.get("request_timeout", 30)
        self.ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

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

    def _parse_vue_data(self, html):
        """从页面中解析 Vue 序列化数据（FOFA 使用 Nuxt.js 服务端渲染）。

        Returns: 解析后的数组，失败返回 None
        """
        pattern = r'<script[^>]*>\s*(\[\["ShallowReactive".*?\])\s*</script>'
        match = re.search(pattern, html, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, IndexError):
            return None

    def _resolve_vue_ref(self, data, ref):
        """解析 Vue 数据中的引用（数字则为数组索引引用）。"""
        if isinstance(ref, int) and 0 <= ref < len(data):
            return data[ref]
        return ref

    def _parse_ips_from_vue(self, vue_data):
        """从 Vue 序列化数据中提取 IP。"""
        try:
            ips = []
            for item in vue_data:
                if not isinstance(item, dict):
                    continue
                if 'assets' in item and 'page' in item:
                    assets_ref = item['assets']
                    assets_list = self._resolve_vue_ref(vue_data, assets_ref)
                    if isinstance(assets_list, list):
                        for asset_ref in assets_list:
                            asset = self._resolve_vue_ref(vue_data, asset_ref)
                            if isinstance(asset, dict) and 'ip' in asset:
                                ip_val = self._resolve_vue_ref(vue_data, asset['ip'])
                                if isinstance(ip_val, str):
                                    # 用正则验证 IP 格式
                                    found = self.ip_pattern.findall(ip_val)
                                    ips.extend(found)
                    if ips:
                        break
            # 去重保持顺序
            seen = set()
            result = []
            for ip in ips:
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
            return result
        except Exception:
            return []

    def _get_total_count(self, vue_data):
        """从 Vue 数据中提取搜索结果总数。"""
        if not vue_data:
            return 0
        try:
            for item in vue_data:
                if not isinstance(item, dict):
                    continue
                if 'assets' in item and 'page' in item:
                    page_ref = item['page']
                    page_data = self._resolve_vue_ref(vue_data, page_ref)
                    if isinstance(page_data, dict) and 'total' in page_data:
                        total = self._resolve_vue_ref(vue_data, page_data['total'])
                        if isinstance(total, (int, float)):
                            return int(total)
            return 0
        except Exception:
            return 0

    def _generate_query_variants(self, base_query, max_variants):
        """生成多个查询变体，按国家/地区划分以获取更多不同的 IP。

        FOFA SSR 只返回第一页（约10条），通过添加不同国家过滤条件获取更多 IP。
        """
        variants = [base_query]  # 第一个是原始查询
        countries = ['US', 'CN', 'JP', 'DE', 'GB', 'FR', 'BR', 'IN', 'KR', 'RU',
                     'CA', 'AU', 'IT', 'ES', 'NL', 'SG', 'HK', 'TW']
        for country in countries:
            if len(variants) >= max_variants:
                break
            variants.append(f'{base_query} && country="{country}"')
        return variants[:max_variants]

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
        """网页爬取模式：通过 Cookie 访问 FOFA 网页，解析 Vue SSR 数据提取 IP。

        FOFA 使用 Nuxt.js 服务端渲染，搜索结果嵌入在 <script> 中的 Vue 序列化数据里。
        由于 SSR 只返回第一页（约 10 条），通过按国家划分生成多个查询变体以获取更多 IP。
        """
        from bs4 import BeautifulSoup

        results = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"
        web_base = "https://fofa.info"

        session = requests.Session()
        session.cookies.update(cookies)

        for query_name in query_names:
            if query_name not in self.queries:
                continue

            query_info = self.queries[query_name]
            base_query = query_info.get("query", "")
            protocol = query_info.get("protocol", query_name)

            try:
                if not base_query:
                    results.append({"protocol": protocol, "error": f"{query_name} 查询语句为空"})
                    continue

                # 计算变体数量：每页约10条，limit/10 向上取整，最少3最多18
                max_variants = max(3, min(18, math.ceil(limit / 10)))
                variants = self._generate_query_variants(base_query, max_variants)

                all_ips = []
                seen_global = set()
                total_count = 0
                last_response = None
                last_lower_text = ""

                for i, variant_query in enumerate(variants):
                    # 达到 limit 提前终止
                    if len(all_ips) >= limit:
                        break

                    # 随机延迟 3-8 秒（降低被封风险）
                    if i > 0:
                        time.sleep(random.uniform(3, 8))

                    headers = {
                        "User-Agent": random.choice(USER_AGENTS),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                    }

                    query_b64 = base64.b64encode(variant_query.encode("utf-8")).decode("utf-8")
                    url = f"{web_base}/result?qbase64={query_b64}&page=1"

                    try:
                        response = session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
                    except Exception:
                        continue  # 跳过该变体，继续下一个

                    last_response = response
                    lower_text = response.text.lower()
                    last_lower_text = lower_text

                    # Cloudflare 检测
                    if response.status_code in (403, 503) or "cf-challenge" in lower_text or "cloudflare" in lower_text:
                        if i == 0:
                            results.append({
                                "protocol": protocol,
                                "error": "FOFA 被 Cloudflare 拦截，Cookie 模式不可用，建议使用 API 密钥",
                            })
                            break  # 第一个就被拦截，后续也不会成功
                        continue  # 后续变体被拦截，跳过

                    # 登录态检测
                    if "login" in lower_text or "sign in" in lower_text or response.status_code in (302, 301):
                        if i == 0:
                            results.append({
                                "protocol": protocol,
                                "error": "Cookie 登录态已过期，请重新获取 Cookie",
                            })
                            break
                        continue

                    # 优先：Vue SSR 数据解析
                    page_ips = []
                    vue_data = self._parse_vue_data(response.text)
                    if vue_data:
                        page_ips = self._parse_ips_from_vue(vue_data)
                        total_count = self._get_total_count(vue_data)

                    # 降级：BeautifulSoup 元素解析（保留原有多选择器逻辑）
                    if not page_ips:
                        soup = BeautifulSoup(response.text, "html.parser")
                        seen_local = set()

                        # 选择器 1: a.target（FOFA 结果页 IP 链接）
                        for link in soup.select("a.target"):
                            text = link.get_text(strip=True)
                            if self.ip_pattern.match(text) and text not in seen_local:
                                seen_local.add(text)
                                page_ips.append(text)
                            href = link.get("href", "")
                            candidate = href.strip()
                            if self.ip_pattern.match(candidate) and candidate not in seen_local:
                                seen_local.add(candidate)
                                page_ips.append(candidate)

                        # 选择器 2: div.r_item a, div.list_module a, div.result-item a
                        if not page_ips:
                            for selector in ["div.r_item a", "div.list_module a", "div.result-item a"]:
                                for link in soup.select(selector):
                                    text = link.get_text(strip=True)
                                    if self.ip_pattern.match(text) and text not in seen_local:
                                        seen_local.add(text)
                                        page_ips.append(text)
                                if page_ips:
                                    break

                        # 选择器 3: span.ip
                        if not page_ips:
                            for el in soup.select("span.ip"):
                                text = el.get_text(strip=True)
                                if self.ip_pattern.match(text) and text not in seen_local:
                                    seen_local.add(text)
                                    page_ips.append(text)

                        # 选择器 4: 所有 a 标签文本（原逻辑兜底）
                        if not page_ips:
                            for link in soup.find_all("a"):
                                text = link.get_text(strip=True)
                                if self.ip_pattern.match(text) and text not in seen_local:
                                    seen_local.add(text)
                                    page_ips.append(text)

                    # 兜底：正则全文提取
                    if not page_ips:
                        page_ips = list(self.ip_pattern.findall(response.text))

                    # 跨变体去重累计
                    for ip in page_ips:
                        if ip not in seen_global:
                            seen_global.add(ip)
                            all_ips.append(ip)
                            if len(all_ips) >= limit:
                                break

                # 所有变体完成：0 结果时不写文件，返回 error 含调试信息
                if not all_ips:
                    flags = []
                    if "login" in last_lower_text or "sign in" in last_lower_text:
                        flags.append("login")
                    if "cf-challenge" in last_lower_text or "cloudflare" in last_lower_text:
                        flags.append("cloudflare")
                    if "upgrade" in last_lower_text or "vip" in last_lower_text:
                        flags.append("vip")
                    if "credits" in last_lower_text:
                        flags.append("credits")
                    flags_str = "、".join(flags) if flags else "无"

                    status_code = last_response.status_code if last_response is not None else 0
                    html_length = len(last_response.text) if last_response is not None else 0

                    error_msg = (
                        f"网页爬取提取到 0 个 IP（{len(variants)} 个变体查询全部无结果，"
                        f"最后状态 status={status_code}, html_length={html_length}, "
                        f"含 {flags_str} 标志）。可能原因：Cookie 登录态失效 / web_query 配额耗尽 / "
                        f"网站改版。建议检查 Cookie 或改用 API 密钥。"
                    )
                    results.append({
                        "protocol": protocol,
                        "error": error_msg,
                        "query": base_query,
                        "source_url": web_base,
                    })
                    continue

                # 写文件（保留原有文件头格式）
                all_ips = all_ips[:limit]
                filename = f"{query_name}_{today_str}.txt"
                output_path = base_path / output_dir / filename

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# FOFA - {protocol} servers\n")
                    f.write(f"# Query: {base_query}\n")
                    f.write(f"# Mode: web-cookie\n")
                    f.write(f"# Fetch time: {datetime.now().isoformat()}\n")
                    f.write(f"# Total results: {len(all_ips)}\n")
                    for ip in all_ips:
                        f.write(f"{ip}\n")

                result_entry = {
                    "path": f"{output_dir}/{filename}",
                    "protocol": protocol,
                    "ip_count": len(all_ips),
                    "query": base_query,
                    "source_url": web_base,
                    "variants_used": len(variants),
                }
                if total_count:
                    result_entry["total_count"] = total_count
                results.append(result_entry)

            except Exception as e:
                results.append({
                    "protocol": protocol,
                    "error": str(e),
                })

        session.close()

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
        from bs4 import BeautifulSoup

        if cookies is None:
            cookies = get_cookies("fofa")
        if not cookies:
            return {"valid": False, "error": "Cookie 未配置"}

        try:
            session = requests.Session()
            session.cookies.update(cookies)
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }

            # 第一步：访问首页检测登录态
            response = session.get("https://fofa.info/", headers=headers, timeout=self.timeout, allow_redirects=True)
            lower_text = response.text.lower()

            # Cloudflare 检测
            if response.status_code in (403, 503) or "cf-challenge" in lower_text or "cloudflare" in lower_text:
                return {"valid": False, "error": "FOFA 被 Cloudflare 拦截，Cookie 模式不可用，建议使用 API 密钥"}

            # 登录态关键词检测
            login_indicators = ['退出', 'logout', '个人中心', '我的资产', '会员中心']
            login_confirmed = any(indicator.lower() in lower_text for indicator in login_indicators)

            if not login_confirmed:
                # 也检测是否被重定向到登录页
                if "login" in lower_text or "sign in" in lower_text or response.status_code in (302, 301):
                    return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}
                return {"valid": False, "error": "Cookie 登录态已过期，请重新获取 Cookie"}

            # 第二步：登录态有效，用测试查询检测搜索结果容器
            test_b64 = base64.b64encode(b"ip=1.1.1.1").decode()
            search_response = session.get(
                f"https://fofa.info/result?qbase64={test_b64}",
                headers=headers, timeout=self.timeout, allow_redirects=True
            )

            result_containers = 0
            ip_count = 0
            total = 0

            # 优先用 Vue SSR 解析
            vue_data = self._parse_vue_data(search_response.text)
            if vue_data:
                vue_ips = self._parse_ips_from_vue(vue_data)
                ip_count = len(vue_ips)
                result_containers = len(vue_ips)  # Vue 解析到的 IP 数即为结果数
                total = self._get_total_count(vue_data)
            else:
                # 降级到元素解析
                soup = BeautifulSoup(search_response.text, "html.parser")
                result_containers = max(
                    len(soup.select("div.list_module")),
                    len(soup.select("div.r_item")),
                    len(soup.select("a.target")),
                    len(soup.select("div.result-item")),
                )
                ip_count = len(set(self.ip_pattern.findall(search_response.text)))

            result = {
                "valid": True,
                "login_confirmed": True,
                "ip_count": ip_count,
                "result_containers": result_containers,
            }
            if total:
                result["total_count"] = total
            if result_containers == 0:
                result["warning"] = "登录态有效但未找到搜索结果容器（可能是 web_query 配额耗尽或网站改版）。"
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