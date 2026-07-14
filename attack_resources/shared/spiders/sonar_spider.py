from __future__ import annotations

import gzip
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..config import SPIDER_CONFIG


class SonarSpider:
    def __init__(self):
        self.config = SPIDER_CONFIG.get("sonar", {})
        self.base_url = self.config.get("base_url", "https://opendata.rapid7.com")
        self.listing_url = self.config.get("listing_url", "https://opendata.rapid7.com/sonar.udp/")
        self.queries = self.config.get("queries", {})
        self.limit_per_query = self.config.get("limit_per_query", 1000)
        self.timeout = self.config.get("timeout", 60)
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0")

    def fetch(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        query_names = params.get("queries", list(self.queries.keys()))
        limit = params.get("limit", self.limit_per_query)
        output_dir = "auto/sonar"

        # 1. Fetch listing page HTML
        try:
            response = requests.get(
                self.listing_url,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
            response.raise_for_status()
            html_text = response.text
        except Exception as e:
            return {"success": False, "error": f"无法获取 Sonar 数据集列表: {e}"}

        # 2. Extract all .csv.gz references from the listing page.
        #    The page structure has evolved: filenames appear inside
        #    <td class="filename">...</td> cells rather than href attributes.
        #    We try both patterns and combine the results for forward-compat.
        href_matches = re.findall(r'href="([^"]+\.csv\.gz)"', html_text)
        td_matches = re.findall(
            r'<td class="filename">\s*([^<]+\.csv\.gz)\s*</td>', html_text
        )
        # Combine; each entry may be a full URL, an absolute path, or a bare filename
        candidates: List[str] = list(href_matches) + list(td_matches)

        results: List[Dict[str, Any]] = []
        today_str = datetime.now().strftime("%Y%m%d")
        base_path = Path(__file__).resolve().parent.parent / "ip_lists"

        # 3. Process each requested protocol
        for query_name in query_names:
            if query_name not in self.queries:
                continue

            query_info = self.queries[query_name]
            protocol = query_info["protocol"]
            sonar_pattern = query_info["sonar_pattern"]

            try:
                # Filter candidates where sonar_pattern is a substring of the
                # basename (case-insensitive) — resilient to naming variations.
                matched = [
                    c for c in candidates
                    if sonar_pattern.lower() in Path(c).name.lower()
                ]

                if not matched:
                    results.append({
                        "protocol": protocol,
                        "error": f"未找到 {query_name} 对应的 Sonar 数据集文件",
                    })
                    continue

                # Pick the LATEST file: sort by leading date prefix
                # (YYYY-MM-DD at start of basename) descending.
                def _date_key(candidate: str) -> str:
                    basename = Path(candidate).name
                    m = re.match(r"(\d{4}-\d{2}-\d{2})", basename)
                    return m.group(1) if m else ""

                matched.sort(key=_date_key, reverse=True)
                latest = matched[0]

                # Construct download URL:
                # - full URL (http/https) → use as-is
                # - absolute path (/...) → join with base_url
                # - bare filename → join with listing_url (which ends with /)
                if latest.startswith("http"):
                    download_url = latest
                elif latest.startswith("/"):
                    download_url = self.base_url + latest
                else:
                    download_url = self.listing_url + latest

                # Download .csv.gz to memory
                dl_response = requests.get(
                    download_url,
                    timeout=self.timeout,
                    headers={"User-Agent": self.user_agent},
                )
                dl_response.raise_for_status()

                # Detect gating: if the server returned HTML instead of gzip
                # (Rapid7 now requires login for some downloads), report clearly.
                content = dl_response.content
                if content[:2] != b"\x1f\x8b":
                    # 判断是商业化 gating（HTML 登录页）还是其他非 gzip 响应
                    head = content[:512].lower()
                    if b"<html" in head or b"login" in head or b"<!doctype" in head:
                        err_msg = "Rapid7 OpenData 已商业化，公开下载受限（服务端返回登录页而非数据文件）。请改用 Shodan 或 FOFA 数据源。"
                    else:
                        err_msg = "下载失败: 服务端返回了非 gzip 数据 (文件可能需要登录)"
                    results.append({
                        "protocol": protocol,
                        "error": err_msg,
                    })
                    continue

                # gzip decompress
                try:
                    decompressed = gzip.decompress(content)
                except Exception as e:
                    results.append({"protocol": protocol, "error": f"gzip 解压失败: {e}"})
                    continue

                # Decode and split lines
                try:
                    text = decompressed.decode("utf-8", errors="replace")
                except Exception as e:
                    results.append({"protocol": protocol, "error": f"UTF-8 解码失败: {e}"})
                    continue

                # Parse first column of each line, validate as IPv4, dedupe (preserve order)
                ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
                seen = set()
                ips: List[str] = []
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    first_field = line.split(",")[0].strip()
                    if ip_pattern.match(first_field) and first_field not in seen:
                        seen.add(first_field)
                        ips.append(first_field)
                    if len(ips) >= limit:
                        break

                # Write output file
                filename = f"{query_name}_{today_str}.txt"
                output_path = base_path / output_dir / filename
                output_path.parent.mkdir(parents=True, exist_ok=True)

                with output_path.open("w", encoding="utf-8") as f:
                    f.write(f"# Sonar - {protocol} servers\n")
                    f.write(f"# Source: {download_url}\n")
                    f.write(f"# Fetch time: {datetime.now().isoformat()}\n")
                    f.write(f"# Total results: {len(ips)}\n")
                    for ip in ips:
                        f.write(f"{ip}\n")

                results.append({
                    "path": f"{output_dir}/{filename}",
                    "protocol": protocol,
                    "ip_count": len(ips),
                    "source_url": download_url,
                })

            except Exception as e:
                results.append({"protocol": protocol, "error": str(e)})

        return {
            "success": True,
            "source": "sonar",
            "source_url": self.base_url,
            "files": results,
            "total_queries": len(query_names),
            "successful": len([r for r in results if "error" not in r]),
        }

    def get_available_queries(self) -> List[Dict[str, str]]:
        return [
            {"name": name, "protocol": info["protocol"], "sonar_pattern": info["sonar_pattern"]}
            for name, info in self.queries.items()
        ]
