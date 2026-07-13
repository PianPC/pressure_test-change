from __future__ import annotations

import re
import time
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
        self.country_list_cache_ttl = self.config.get("country_list_cache_ttl", 86400)
        self._country_list_cache: List[Dict[str, str]] | None = None
        self._country_list_cache_ts: float = 0

    def fetch(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        countries = params.get("countries", list(self.target_countries.keys()))
        output_dir = params.get("output_dir", "auto/ipdeny")

        results = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"

        country_map = {c["code"]: c["name"] for c in self.fetch_country_list()}
        for code, name in self.target_countries.items():
            country_map[code] = name

        for country_code in countries:
            country_name = country_map.get(country_code)
            if country_name is None:
                results.append({
                    "country": country_code,
                    "country_name": country_code,
                    "error": "Country code not available on IPdeny",
                })
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
                    f.write(f"# IPdeny - {country_name} IP ranges\n")
                    f.write(f"# Source: {url}\n")
                    f.write(f"# Fetch time: {datetime.now().isoformat()}\n")
                    f.write(f"# Country: {country_code} ({country_name})\n")
                    f.write(content)

                results.append({
                    "path": f"{output_dir}/{filename}",
                    "country": country_code,
                    "country_name": country_name,
                    "protocol": "tcp",
                    "ip_count": ip_count,
                    "source_url": url,
                })

            except Exception as e:
                results.append({
                    "country": country_code,
                    "country_name": country_name,
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

    def fetch_country_list(self) -> List[Dict[str, str]]:
        if (
            self._country_list_cache is not None
            and time.time() - self._country_list_cache_ts < self.country_list_cache_ttl
        ):
            return self._country_list_cache

        try:
            response = requests.get(
                self.base_url,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
            response.raise_for_status()

            pattern = r"([A-Z][A-Z' ]+?)\s*\(([A-Z]{2})\)\s*\[download\s*<a[^>]*>([a-z]{2})\.zone</a>\]"
            matches = re.findall(pattern, response.text)

            if not matches:
                raise ValueError("No country entries found on IPdeny page")

            seen = set()
            countries: List[Dict[str, str]] = []
            for name_raw, _upper_code, lower_code in matches:
                if lower_code in seen:
                    continue
                seen.add(lower_code)
                countries.append(
                    {"code": lower_code, "name": name_raw.strip().title()}
                )

            countries.sort(key=lambda c: c["code"])
            self._country_list_cache = countries
            self._country_list_cache_ts = time.time()
            return countries
        except Exception:
            fallback = [
                {"code": code, "name": name}
                for code, name in self.target_countries.items()
            ]
            self._country_list_cache = fallback
            self._country_list_cache_ts = time.time()
            return fallback

    def get_available_countries(self) -> List[Dict[str, str]]:
        return self.fetch_country_list()