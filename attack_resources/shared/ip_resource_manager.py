from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import SPIDER_CONFIG
from .ip_resource_catalog import (
    ALL_PROTOCOLS,
    AUTO_SOURCES,
    build_resource_record,
    count_ip_entries,
    list_shared_resources,
    load_resource_metadata,
    metadata_sidecar_path,
    resolve_shared_resource_path,
    save_resource_metadata,
)

COUNTRY_CODES = {
    "cn": "China",
    "ru": "Russia",
    "us": "United States",
    "jp": "Japan",
    "uk": "United Kingdom",
    "de": "Germany",
    "fr": "France",
    "ca": "Canada",
    "au": "Australia",
    "br": "Brazil",
    "kr": "South Korea",
    "in": "India",
    "it": "Italy",
    "es": "Spain",
    "nl": "Netherlands",
}


class IPResourceManager:
    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path) if base_path else Path(__file__).resolve().parent / "ip_lists"
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.attack_resources_root = self.base_path.parent.parent

    def list_resources(
        self,
        filter_type: Optional[str] = None,
        filter_source: Optional[str] = None,
        filter_country: Optional[str] = None,
        filter_protocol: Optional[str] = None,
    ) -> Dict[str, Any]:
        resources: List[Dict[str, Any]] = []
        seen_sources = set()
        seen_countries = set()
        seen_protocols = set()

        for resource in list_shared_resources(self.base_path):
            if filter_type and resource.get("type") != filter_type:
                continue
            if filter_source and resource.get("source") != filter_source:
                continue
            if filter_country and resource.get("country") != filter_country:
                continue
            if filter_protocol and filter_protocol not in resource.get("protocols", []):
                continue
            resources.append(resource)
            if resource.get("source"):
                seen_sources.add(resource["source"])
            if resource.get("country"):
                seen_countries.add(resource["country"])
            for protocol in resource.get("protocols", []):
                seen_protocols.add(protocol)

        resources.sort(
            key=lambda item: (
                item.get("is_shared") is False,
                item.get("display_name", item.get("name", "")).lower(),
            )
        )
        return {
            "resources": resources,
            "filters": {
                "types": ["manual", "auto", "legacy"],
                "sources": sorted(seen_sources),
                "countries": sorted(seen_countries),
                "protocols": sorted(seen_protocols),
            },
        }

    def read_resource(self, path: str) -> Dict[str, Any]:
        full_path = self._resolve_path(path)
        if not full_path.exists():
            raise FileNotFoundError(f"Resource not found: {path}")
        content = full_path.read_text(encoding="utf-8", errors="replace")
        record = build_resource_record(
            full_path,
            self.attack_resources_root,
            shared_root=self.base_path,
            root_base=self.base_path,
        )
        record.update(
            {
                "content": content,
                "path": record["id"],
                "metadata": self.get_resource_metadata(path),
            }
        )
        return record

    def write_resource(self, path: str, content: str) -> Dict[str, Any]:
        full_path = self._resolve_path(path)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        record = build_resource_record(
            full_path,
            self.attack_resources_root,
            shared_root=self.base_path,
            root_base=self.base_path,
        )
        return {
            "name": record["display_name"],
            "filename": record["filename"],
            "path": record["id"],
            "size_bytes": record["size_bytes"],
            "non_empty_lines": record["non_empty_lines"],
        }

    def create_resource(
        self,
        filename: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if "/" in filename or "\\" in filename:
            raise ValueError("Filename cannot contain path separators")
        if not filename.endswith(".txt"):
            filename = f"{filename}.txt"

        full_path = self.base_path / filename
        if full_path.exists():
            raise FileExistsError(f"Resource already exists: {filename}")

        full_path.write_text(content, encoding="utf-8")
        merged_metadata = {
            "type": "manual",
            "source": "manual",
            "protocols": list(ALL_PROTOCOLS),
            "updated_at": datetime.now().isoformat(),
        }
        if metadata:
            merged_metadata.update(metadata)
        save_resource_metadata(full_path, merged_metadata)

        record = build_resource_record(
            full_path,
            self.attack_resources_root,
            shared_root=self.base_path,
            root_base=self.base_path,
        )
        return {
            "name": record["display_name"],
            "filename": record["filename"],
            "path": record["id"],
            "type": record["type"],
            "size_bytes": record["size_bytes"],
            "non_empty_lines": record["non_empty_lines"],
        }

    def delete_resource(self, path: str) -> bool:
        full_path = self._resolve_path(path)
        if not full_path.exists():
            return False
        full_path.unlink()
        sidecar = metadata_sidecar_path(full_path)
        if sidecar.exists():
            sidecar.unlink()
        return True

    def get_resource_metadata(self, path: str) -> Dict[str, Any]:
        full_path = self._resolve_path(path)
        return load_resource_metadata(full_path)

    def update_resource_metadata(self, path: str, metadata: Dict[str, Any]) -> None:
        full_path = self._resolve_path(path)
        current = load_resource_metadata(full_path)
        current.update(metadata)
        current.setdefault("updated_at", datetime.now().isoformat())
        save_resource_metadata(full_path, current)

    def fetch_auto_resources(self, spider_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from .spiders import SPIDERS

        if spider_name not in SPIDERS:
            raise ValueError(f"Unknown spider: {spider_name}")

        spider = SPIDERS[spider_name]
        result = spider.fetch(params)
        if result.get("success") and "files" in result:
            for file_info in result["files"]:
                resource_path = file_info.get("path")
                if not resource_path:
                    continue
                full_path = self.base_path / resource_path
                if not full_path.exists():
                    continue
                metadata = load_resource_metadata(full_path)
                metadata.update(
                    {
                        "type": "auto",
                        "source": spider_name,
                        "source_url": file_info.get("source_url") or result.get("source_url", ""),
                        "ip_count": file_info.get("ip_count", count_ip_entries(full_path)),
                        "fetch_time": datetime.now().isoformat(),
                        "updated_at": datetime.now().isoformat(),
                        "protocols": _protocol_list_for_auto(file_info),
                        "protocol": file_info.get("protocol"),
                        "country": file_info.get("country"),
                        "country_name": file_info.get("country_name"),
                        "shared": True,
                    }
                )
                save_resource_metadata(full_path, metadata)
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

        if not output_name.endswith(".txt"):
            output_name = f"{output_name}.txt"
        output_path = self.base_path / output_name
        if output_path.exists():
            raise FileExistsError(f"Output file already exists: {output_name}")

        with output_path.open("w", encoding="utf-8") as handle:
            handle.write(f"# Merged IP list ({len(sources)} sources)\n")
            handle.write(f"# Generated at: {datetime.now().isoformat()}\n")
            handle.write(f"# Sources: {', '.join(sources)}\n")
            for ip in sorted(merged_ips):
                handle.write(f"{ip}\n")

        save_resource_metadata(
            output_path,
            {
                "type": "manual",
                "source": "manual",
                "protocols": list(ALL_PROTOCOLS),
                "updated_at": datetime.now().isoformat(),
                "merged_from": sources,
            },
        )
        record = build_resource_record(
            output_path,
            self.attack_resources_root,
            shared_root=self.base_path,
            root_base=self.base_path,
        )
        return {
            "name": record["display_name"],
            "filename": record["filename"],
            "path": record["id"],
            "ip_count": len(merged_ips),
            "sources_merged": sources,
        }

    def cleanup_expired_resources(self, max_days: int = 7) -> Dict[str, Any]:
        deleted: List[str] = []
        skipped: List[str] = []
        now = datetime.now()

        for resource in list_shared_resources(self.base_path):
            if resource.get("source") not in AUTO_SOURCES:
                skipped.append(resource["path"])
                continue
            file_path = Path(resource["full_path"])
            age_days = (now - datetime.fromtimestamp(file_path.stat().st_mtime)).days
            if age_days > max_days:
                sidecar = metadata_sidecar_path(file_path)
                file_path.unlink(missing_ok=True)
                if sidecar.exists():
                    sidecar.unlink()
                deleted.append(resource["path"])
            else:
                skipped.append(resource["path"])

        return {"deleted": deleted, "skipped": skipped, "total_deleted": len(deleted)}

    def _resolve_path(self, path_str: str) -> Path:
        resolved = resolve_shared_resource_path(path_str, self.base_path)
        if resolved:
            return resolved

        normalized = str(path_str or "").strip().replace("\\", "/")
        if normalized.startswith("manual/"):
            return self.base_path / Path(normalized[7:]).name
        if normalized.startswith("auto/"):
            return self.base_path / normalized
        if "/" not in normalized and "\\" not in normalized:
            return self.base_path / normalized
        return self.base_path / normalized

    def get_source_info(self) -> List[Dict[str, Any]]:
        sources = []
        for source_name in ["manual", "ipdeny", "shodan", "fofa", "maxmind", "legacy"]:
            config = SPIDER_CONFIG.get(source_name, {}) if source_name in SPIDER_CONFIG else {}
            sources.append(
                {
                    "name": source_name,
                    "display_name": _source_display_name(source_name),
                    "enabled": True if source_name in {"manual", "legacy"} else config.get("enabled", False),
                    "description": _source_description(source_name),
                }
            )
        return sources

    def get_country_list(self) -> List[Dict[str, Any]]:
        return [{"code": code, "name": name} for code, name in COUNTRY_CODES.items()]



def _protocol_list_for_auto(file_info: Dict[str, Any]) -> List[str]:
    protocol = str(file_info.get("protocol") or "").strip().lower()
    if protocol in ALL_PROTOCOLS:
        return [protocol]
    return ["tcp"] if str(file_info.get("country") or "").strip() else list(ALL_PROTOCOLS)



def _source_display_name(source_name: str) -> str:
    return {
        "manual": "Manual",
        "legacy": "Legacy",
        "ipdeny": "IPdeny",
        "shodan": "Shodan",
        "fofa": "FOFA",
        "maxmind": "MaxMind",
    }.get(source_name, source_name.title())



def _source_description(source: str) -> str:
    descriptions = {
        "manual": "Manually maintained shared IP resources.",
        "legacy": "Protocol-local compatibility resources discovered from legacy directories.",
        "ipdeny": "Country and region IP ranges fetched from IPdeny.",
        "shodan": "Protocol-specific IP resources fetched from Shodan.",
        "fofa": "Protocol-specific IP resources fetched from FOFA.",
        "maxmind": "GeoIP-derived IP resources.",
    }
    return descriptions.get(source, "")


resource_manager = IPResourceManager()
