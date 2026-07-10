from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..config import SPIDER_CONFIG


class IPDenySpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("ipdeny", {})
        self.base_url = self.config.get("base_url", "https://www.ipdeny.com/ipblocks/")
        self.data_url = self.config.get("data_url", "https://www.ipdeny.com/ipblocks/data/countries/")
        self.target_countries = self.config.get("target_countries", {})
        self.timeout = self.config.get("request_timeout", 30)
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0")

    def fetch(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        countries = params.get("countries", list(self.target_countries.keys()))
        output_dir = params.get("output_dir", "auto/ipdeny")

        results = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"

        for country_code in countries:
            if country_code not in self.target_countries:
                continue

            try:
                url = f"{self.data_url}{country_code}.zone"
                response = requests.get(url, timeout=self.timeout, headers={"User-Agent": self.user_agent})
                response.raise_for_status()

                content = response.text
                ip_count = self._count_ips(content)

                filename = f"{country_code}_{today_str}.txt"
                output_path = base_path / output_dir / filename

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# IPdeny - {self.target_countries[country_code]} IP ranges\n")
                    f.write(f"# Source: {url}\n")
                    f.write(f"# Fetch time: {datetime.now().isoformat()}\n")
                    f.write(f"# Country: {country_code} ({self.target_countries[country_code]})\n")
                    f.write(content)

                results.append({
                    "path": f"{output_dir}/{filename}",
                    "country": country_code,
                    "country_name": self.target_countries[country_code],
                    "protocol": "tcp",
                    "ip_count": ip_count,
                    "source_url": url,
                })

            except Exception as e:
                results.append({
                    "country": country_code,
                    "country_name": self.target_countries[country_code],
                    "error": str(e),
                })

        return {
            "success": True,
            "source": "ipdeny",
            "source_url": self.base_url,
            "files": results,
            "total_countries": len(countries),
            "successful": len([r for r in results if "error" not in r]),
        }

    def _count_ips(self, content: str) -> int:
        count = 0
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                if self._is_valid_cidr(line):
                    count += 1
        return count

    def _is_valid_cidr(self, cidr: str) -> bool:
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
        if not re.match(pattern, cidr):
            return False
        parts = cidr.split("/")
        ip = parts[0]
        prefix = int(parts[1])
        if prefix < 0 or prefix > 32:
            return False
        for octet in ip.split("."):
            if int(octet) < 0 or int(octet) > 255:
                return False
        return True

    def get_available_countries(self) -> List[Dict[str, str]]:
        return [
            {"code": code, "name": name}
            for code, name in self.target_countries.items()
        ]