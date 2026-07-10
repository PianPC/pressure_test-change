from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import SPIDER_CONFIG

COUNTRY_CODES = {
    "cn": "中国",
    "ru": "俄罗斯",
    "us": "美国",
    "jp": "日本",
    "uk": "英国",
    "de": "德国",
    "fr": "法国",
    "ca": "加拿大",
    "au": "澳大利亚",
    "br": "巴西",
    "kr": "韩国",
    "in": "印度",
    "it": "意大利",
    "es": "西班牙",
    "nl": "荷兰",
}

PROTOCOL_NAMES = {
    "tcp": "TCP",
    "dns": "DNS",
    "memcached": "Memcached",
    "ntp": "NTP",
}


class IPResourceManager:
    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path) if base_path else Path(__file__).resolve().parent / "ip_lists"
        self.manual_path = self.base_path / "manual"
        self.auto_path = self.base_path / "auto"
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        self.manual_path.mkdir(parents=True, exist_ok=True)
        (self.auto_path / "ipdeny").mkdir(parents=True, exist_ok=True)
        (self.auto_path / "shodan").mkdir(parents=True, exist_ok=True)
        (self.auto_path / "fofa").mkdir(parents=True, exist_ok=True)
        (self.auto_path / "maxmind").mkdir(parents=True, exist_ok=True)

    def list_resources(
        self,
        filter_type: Optional[str] = None,
        filter_source: Optional[str] = None,
        filter_country: Optional[str] = None,
        filter_protocol: Optional[str] = None,
    ) -> Dict[str, Any]:
        resources = []
        filters = {"types": ["manual", "auto"], "sources": [], "countries": [], "protocols": []}

        seen_sources = set()
        seen_countries = set()
        seen_protocols = set()

        for resource in self._list_manual_resources():
            if filter_type and resource["type"] != filter_type:
                continue
            resources.append(resource)

        for resource in self._list_auto_resources():
            if filter_type and resource["type"] != filter_type:
                continue
            if filter_source and resource["source"] != filter_source:
                continue
            if filter_country and resource.get("country") != filter_country:
                continue
            if filter_protocol and resource.get("protocol") != filter_protocol:
                continue

            resources.append(resource)
            if resource.get("source"):
                seen_sources.add(resource["source"])
            if resource.get("country"):
                seen_countries.add(resource["country"])
            if resource.get("protocol"):
                seen_protocols.add(resource["protocol"])

        filters["sources"] = sorted(seen_sources)
        filters["countries"] = sorted(seen_countries)
        filters["protocols"] = sorted(seen_protocols)

        return {"resources": resources, "filters": filters}

    def _list_manual_resources(self) -> List[Dict[str, Any]]:
        resources = []
        if not self.manual_path.exists():
            return resources

        for path in sorted(self.manual_path.glob("*.txt")):
            if not path.is_file():
                continue
            line_count = self._count_non_empty_lines(path)
            resources.append({
                "name": path.stem,
                "filename": path.name,
                "path": f"manual/{path.name}",
                "full_path": str(path),
                "type": "manual",
                "source": None,
                "country": None,
                "country_name": None,
                "protocol": None,
                "protocol_name": None,
                "ip_count": line_count,
                "fetch_time": None,
                "size_bytes": path.stat().st_size,
                "non_empty_lines": line_count,
                "is_auto": False,
            })
        return resources

    def _list_auto_resources(self) -> List[Dict[str, Any]]:
        resources = []

        for source_dir in sorted(self.auto_path.iterdir()):
            if not source_dir.is_dir():
                continue
            source = source_dir.name

            for path in sorted(source_dir.glob("*.txt")):
                if not path.is_file():
                    continue

                meta = self._parse_auto_filename(path.name, source)
                if not meta:
                    continue

                line_count = self._count_non_empty_lines(path)
                metadata = self._load_metadata(source_dir, path.name)

                resource = {
                    "name": path.stem,
                    "filename": path.name,
                    "path": f"auto/{source}/{path.name}",
                    "full_path": str(path),
                    "type": "auto",
                    "source": source,
                    "source_name": self._get_source_name(source),
                    "country": meta.get("country"),
                    "country_name": meta.get("country_name"),
                    "protocol": meta.get("protocol"),
                    "protocol_name": meta.get("protocol_name"),
                    "ip_count": line_count,
                    "fetch_time": metadata.get("fetch_time"),
                    "size_bytes": path.stat().st_size,
                    "non_empty_lines": line_count,
                    "is_auto": True,
                    "metadata": metadata,
                }
                resources.append(resource)

        return resources

    def _parse_auto_filename(self, filename: str, source: str) -> Dict[str, Any]:
        stem = filename.replace(".txt", "")

        if source == "ipdeny":
            match = re.match(r"^([a-z]{2})_(\d{8})$", stem)
            if match:
                country_code = match.group(1)
                return {
                    "country": country_code,
                    "country_name": COUNTRY_CODES.get(country_code, country_code.upper()),
                    "protocol": "tcp",
                    "protocol_name": "TCP",
                }

        elif source in ("shodan", "fofa"):
            match = re.match(r"^([a-z_]+)_(\d{8})$", stem)
            if match:
                protocol = match.group(1)
                return {
                    "country": None,
                    "country_name": None,
                    "protocol": protocol,
                    "protocol_name": PROTOCOL_NAMES.get(protocol, protocol.title()),
                }

        elif source == "maxmind":
            match = re.match(r"^([a-z]{2})_geoip$", stem)
            if match:
                country_code = match.group(1)
                return {
                    "country": country_code,
                    "country_name": COUNTRY_CODES.get(country_code, country_code.upper()),
                    "protocol": "tcp",
                    "protocol_name": "TCP",
                }

        return {}

    def _load_metadata(self, source_dir: Path, filename: str) -> Dict[str, Any]:
        metadata_path = source_dir / "metadata.json"
        if not metadata_path.exists():
            return {}

        try:
            with metadata_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _get_source_name(self, source: str) -> str:
        names = {"ipdeny": "IPdeny", "shodan": "Shodan", "fofa": "FOFA", "maxmind": "MaxMind"}
        return names.get(source, source.title())

    def read_resource(self, path: str) -> Dict[str, Any]:
        full_path = self._resolve_path(path)
        if not full_path.exists():
            raise FileNotFoundError(f"Resource not found: {path}")

        content = full_path.read_text(encoding="utf-8", errors="replace")
        metadata = self._get_resource_metadata(path)

        return {
            "name": full_path.stem,
            "filename": full_path.name,
            "path": path,
            "type": "manual" if "manual" in path else "auto",
            "content": content,
            "size_bytes": full_path.stat().st_size,
            "non_empty_lines": self._count_non_empty_lines(full_path),
            "metadata": metadata,
        }

    def write_resource(self, path: str, content: str) -> Dict[str, Any]:
        full_path = self._resolve_path(path)
        if not full_path.parent.exists():
            full_path.parent.mkdir(parents=True, exist_ok=True)

        full_path.write_text(content, encoding="utf-8")

        return {
            "name": full_path.stem,
            "filename": full_path.name,
            "path": path,
            "size_bytes": full_path.stat().st_size,
            "non_empty_lines": self._count_non_empty_lines(full_path),
        }

    def create_resource(self, filename: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if "/" in filename or "\\" in filename:
            raise ValueError("Filename cannot contain path separators")

        full_path = self.manual_path / filename
        if full_path.exists():
            raise FileExistsError(f"Resource already exists: {filename}")

        full_path.write_text(content, encoding="utf-8")

        if metadata:
            metadata_path = self.manual_path / f".{filename}.metadata.json"
            with metadata_path.open("w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)

        return {
            "name": full_path.stem,
            "filename": full_path.name,
            "path": f"manual/{filename}",
            "type": "manual",
            "size_bytes": full_path.stat().st_size,
            "non_empty_lines": self._count_non_empty_lines(full_path),
        }

    def delete_resource(self, path: str) -> bool:
        full_path = self._resolve_path(path)
        if not full_path.exists():
            return False

        full_path.unlink()

        metadata_path = full_path.parent / f".{full_path.name}.metadata.json"
        if metadata_path.exists():
            metadata_path.unlink()

        return True

    def get_resource_metadata(self, path: str) -> Dict[str, Any]:
        full_path = self._resolve_path(path)

        if "manual" in path:
            metadata_path = self.manual_path / f".{full_path.name}.metadata.json"
            if metadata_path.exists():
                try:
                    with metadata_path.open("r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
            return {}

        source_dir = full_path.parent
        return self._load_metadata(source_dir, full_path.name)

    def update_resource_metadata(self, path: str, metadata: Dict[str, Any]) -> None:
        full_path = self._resolve_path(path)

        if "manual" in path:
            metadata_path = self.manual_path / f".{full_path.name}.metadata.json"
            with metadata_path.open("w", encoding="utf-8") as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
        else:
            source_dir = full_path.parent
            metadata_path = source_dir / "metadata.json"
            if metadata_path.exists():
                try:
                    with metadata_path.open("r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    existing = {}
                existing.update(metadata)
                with metadata_path.open("w", encoding="utf-8") as f:
                    json.dump(existing, f, ensure_ascii=False, indent=2)

    def fetch_auto_resources(self, spider_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from .spiders import SPIDERS

        if spider_name not in SPIDERS:
            raise ValueError(f"Unknown spider: {spider_name}")

        spider = SPIDERS[spider_name]
        result = spider.fetch(params)

        if result.get("success") and "files" in result:
            for file_info in result["files"]:
                full_path = self.base_path / file_info["path"]
                metadata = {
                    "source": spider_name,
                    "source_url": result.get("source_url", ""),
                    "ip_count": file_info.get("ip_count", 0),
                    "fetch_time": datetime.now().isoformat(),
                    "update_interval_hours": SPIDER_CONFIG.get(spider_name, {}).get("update_interval_hours", 24),
                }
                if file_info.get("country"):
                    metadata["country"] = file_info["country"]
                    metadata["country_name"] = file_info.get("country_name", "")
                if file_info.get("protocol"):
                    metadata["protocol"] = file_info["protocol"]

                source_dir = full_path.parent
                metadata_path = source_dir / "metadata.json"
                if metadata_path.exists():
                    try:
                        with metadata_path.open("r", encoding="utf-8") as f:
                            existing = json.load(f)
                        existing.update(metadata)
                    except Exception:
                        existing = metadata
                else:
                    existing = metadata

                with metadata_path.open("w", encoding="utf-8") as f:
                    json.dump(existing, f, ensure_ascii=False, indent=2)

        return result

    def merge_resources(self, sources: List[str], output_name: str) -> Dict[str, Any]:
        merged_ips = set()

        for source_path in sources:
            full_path = self._resolve_path(source_path)
            if not full_path.exists():
                continue
            content = full_path.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ip = line.split(",")[0].strip()
                    if ip:
                        merged_ips.add(ip)

        output_path = self.manual_path / output_name
        if output_path.exists():
            raise FileExistsError(f"Output file already exists: {output_name}")

        with output_path.open("w", encoding="utf-8") as f:
            f.write(f"# Merged IP list ({len(sources)} sources)\n")
            f.write(f"# Generated at: {datetime.now().isoformat()}\n")
            f.write(f"# Sources: {', '.join(sources)}\n")
            for ip in sorted(merged_ips):
                f.write(f"{ip}\n")

        return {
            "name": output_path.stem,
            "filename": output_path.name,
            "path": f"manual/{output_name}",
            "ip_count": len(merged_ips),
            "sources_merged": sources,
        }

    def cleanup_expired_resources(self, max_days: int = 7) -> Dict[str, Any]:
        deleted = []
        skipped = []

        for source_dir in self.auto_path.iterdir():
            if not source_dir.is_dir():
                continue

            for path in source_dir.glob("*.txt"):
                if not path.is_file():
                    continue

                mtime = datetime.fromtimestamp(path.stat().st_mtime)
                age_days = (datetime.now() - mtime).days

                if age_days > max_days:
                    path.unlink()
                    deleted.append(str(path.relative_to(self.base_path)))
                else:
                    skipped.append(str(path.relative_to(self.base_path)))

        return {"deleted": deleted, "skipped": skipped, "total_deleted": len(deleted)}

    def _resolve_path(self, path_str: str) -> Path:
        if path_str.startswith("manual/"):
            return self.manual_path / path_str[7:]
        elif path_str.startswith("auto/"):
            return self.auto_path / path_str[5:]
        elif "/" not in path_str and "\\" not in path_str:
            manual_candidate = self.manual_path / path_str
            if manual_candidate.exists():
                return manual_candidate
            for source_dir in self.auto_path.iterdir():
                if source_dir.is_dir():
                    candidate = source_dir / path_str
                    if candidate.exists():
                        return candidate
            return self.manual_path / path_str
        else:
            return self.base_path / path_str

    def _count_non_empty_lines(self, path: Path) -> int:
        count = 0
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count

    def get_source_info(self) -> List[Dict[str, Any]]:
        sources = []
        for source_name in ["ipdeny", "shodan", "fofa", "maxmind"]:
            config = SPIDER_CONFIG.get(source_name, {})
            sources.append({
                "name": source_name,
                "display_name": self._get_source_name(source_name),
                "enabled": config.get("enabled", False),
                "description": self._get_source_description(source_name),
            })
        return sources

    def _get_source_description(self, source: str) -> str:
        descriptions = {
            "ipdeny": "获取国家/地区IP段（免费）",
            "shodan": "搜索互联网设备服务（需要API密钥）",
            "fofa": "搜索互联网设备服务（需要API密钥）",
            "maxmind": "GeoIP数据库导出（需要下载数据库）",
        }
        return descriptions.get(source, "")

    def get_country_list(self) -> List[Dict[str, Any]]:
        return [
            {"code": code, "name": name}
            for code, name in COUNTRY_CODES.items()
        ]


resource_manager = IPResourceManager()