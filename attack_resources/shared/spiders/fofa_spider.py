from __future__ import annotations

import base64
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..config import SPIDER_CONFIG


class FOFASpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("fofa", {})
        self.email = self.config.get("email", "")
        self.key = self.config.get("key", "")
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

        if not self.email or not self.key:
            return {"success": False, "error": "FOFA email or key not configured"}

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
                sign_str = f"{self.email}{self.key}{timestamp}{query_b64}"
                sign = hashlib.md5(sign_str.encode()).hexdigest()

                url = f"{self.api_url}?email={self.email}&key={self.key}&qbase64={query_b64}&size={limit}&sign={sign}"
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

    def check_credentials(self) -> Dict[str, Any]:
        if not self.email or not self.key:
            return {"valid": False, "error": "Email or key not set"}

        try:
            test_query = base64.b64encode("ip=1.1.1.1".encode()).decode()
            timestamp = str(int(datetime.now().timestamp()))
            sign_str = f"{self.email}{self.key}{timestamp}{test_query}"
            sign = hashlib.md5(sign_str.encode()).hexdigest()

            url = f"{self.api_url}?email={self.email}&key={self.key}&qbase64={test_query}&size=1&sign={sign}"
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