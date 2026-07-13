from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..config import SPIDER_CONFIG
from ..credential_store import get_credentials


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
        if not api_key:
            return {"success": False, "error": "Shodan API key not configured"}

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