from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

ALL_PROTOCOLS = ("tcp", "dns", "memcached", "ntp")

PROTOCOL_NAMES = {
    "tcp": "TCP",
    "dns": "DNS",
    "memcached": "Memcached",
    "ntp": "NTP",
}

SOURCE_NAMES = {
    "manual": "Manual",
    "legacy": "Legacy",
    "ipdeny": "IPdeny",
    "shodan": "Shodan",
    "fofa": "FOFA",
    "maxmind": "MaxMind",
}

AUTO_SOURCES = {"ipdeny", "shodan", "fofa", "maxmind"}


def shared_ip_root(attack_resources_root: str | Path) -> Path:
    return Path(attack_resources_root) / "shared" / "ip_lists"


def legacy_resource_roots(protocol: str, attack_resources_root: str | Path) -> list[Path]:
    protocol_root = Path(attack_resources_root) / protocol / "resources"
    roots = [protocol_root / "ip_lists"]
    if protocol != "tcp":
        roots.append(protocol_root)
    return roots


def count_ip_entries(path: str | Path) -> int:
    file_path = Path(path)
    if not file_path.exists():
        return 0

    count = 0
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                count += 1
    return count


def metadata_sidecar_path(file_path: str | Path) -> Path:
    path = Path(file_path)
    return path.parent / f".{path.name}.metadata.json"


def load_resource_metadata(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    for candidate in (metadata_sidecar_path(path), path.parent / "metadata.json"):
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def save_resource_metadata(file_path: str | Path, metadata: dict[str, Any]) -> None:
    metadata_path = metadata_sidecar_path(file_path)
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def resource_id_from_path(file_path: str | Path, attack_resources_root: str | Path) -> str:
    path = Path(file_path).resolve()
    root = Path(attack_resources_root).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError:
        return path.name
    return f"attack_resources/{relative.as_posix()}"


def build_resource_record(
    file_path: str | Path,
    attack_resources_root: str | Path,
    *,
    shared_root: str | Path | None = None,
    owning_protocol: str | None = None,
    root_base: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(file_path)
    root = Path(attack_resources_root)
    shared = Path(shared_root) if shared_root else shared_ip_root(root)
    metadata = load_resource_metadata(path)

    protocols = _normalize_protocols(
        metadata.get("protocols")
        or metadata.get("available_protocols")
        or metadata.get("protocol")
        or metadata.get("source_protocol"),
    )
    if not protocols:
        if owning_protocol:
            protocols = [owning_protocol]
        else:
            protocols = list(ALL_PROTOCOLS)

    source = str(metadata.get("source") or metadata.get("origin") or "").strip().lower() or "legacy"
    resource_type = str(metadata.get("type") or ("auto" if source in AUTO_SOURCES else "manual")).strip().lower()
    updated_at = (
        str(metadata.get("updated_at") or metadata.get("fetch_time") or "").strip()
        or datetime.fromtimestamp(path.stat().st_mtime).isoformat()
    )
    count = count_ip_entries(path)
    size_bytes = path.stat().st_size
    is_shared = _is_relative_to(path.resolve(), shared.resolve())

    sub_dir = ""
    if root_base:
        root_base_path = Path(root_base)
        try:
            relative_parent = path.relative_to(root_base_path).parent
            sub_dir = "" if str(relative_parent) == "." else relative_parent.as_posix()
        except ValueError:
            sub_dir = ""

    protocol_names = [PROTOCOL_NAMES.get(protocol, protocol.upper()) for protocol in protocols]

    if is_shared:
        location_label = "共享池"
    elif owning_protocol:
        location_label = f"{PROTOCOL_NAMES.get(owning_protocol, owning_protocol.upper())} 目录"
    else:
        location_label = "兼容目录"

    return {
        "id": resource_id_from_path(path, root),
        "name": path.name,
        "filename": path.name,
        "display_name": path.stem,
        "path": resource_id_from_path(path, root),
        "full_path": str(path),
        "type": resource_type,
        "source": source,
        "source_name": SOURCE_NAMES.get(source, source.title() if source else "Legacy"),
        "country": metadata.get("country"),
        "country_name": metadata.get("country_name"),
        "protocol": protocols[0] if len(protocols) == 1 else None,
        "protocol_name": protocol_names[0] if len(protocol_names) == 1 else None,
        "protocols": protocols,
        "protocol_names": protocol_names,
        "count": count,
        "entry_count": count,
        "ip_count": count,
        "non_empty_lines": count,
        "size_bytes": size_bytes,
        "bytes": size_bytes,
        "fetch_time": metadata.get("fetch_time"),
        "updated_at": updated_at,
        "editable": True,
        "is_shared": is_shared,
        "legacy": source == "legacy",
        "location_label": location_label,
        "sub_dir": sub_dir,
        "metadata": metadata,
    }


def list_shared_resources(shared_root: str | Path) -> list[dict[str, Any]]:
    root = Path(shared_root)
    attack_root = _attack_resources_root_from_shared_root(root)
    seen: set[Path] = set()
    resources: list[dict[str, Any]] = []

    for file_path in _iter_text_files(root):
        resolved = file_path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        resources.append(
            build_resource_record(
                file_path,
                attack_root,
                shared_root=root,
                root_base=root,
            )
        )
    return resources


def list_protocol_resources(protocol: str, attack_resources_root: str | Path) -> list[dict[str, Any]]:
    root = Path(attack_resources_root)
    shared_root = shared_ip_root(root)
    seen: set[Path] = set()
    resources: list[dict[str, Any]] = []

    for file_path in _iter_text_files(shared_root):
        resolved = file_path.resolve()
        if resolved in seen:
            continue
        record = build_resource_record(
            file_path,
            root,
            shared_root=shared_root,
            root_base=shared_root,
        )
        if protocol in record["protocols"]:
            seen.add(resolved)
            resources.append(record)

    for legacy_root in legacy_resource_roots(protocol, root):
        for file_path in _iter_text_files(legacy_root):
            resolved = file_path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            resources.append(
                build_resource_record(
                    file_path,
                    root,
                    shared_root=shared_root,
                    owning_protocol=protocol,
                    root_base=legacy_root,
                )
            )

    return resources


def resolve_shared_resource_path(identifier: str, shared_root: str | Path) -> Path | None:
    root = Path(shared_root)
    attack_root = _attack_resources_root_from_shared_root(root)
    return _resolve_resource_path(
        identifier,
        attack_root,
        search_roots=[root],
    )


def resolve_protocol_resource_path(
    protocol: str,
    identifier: str,
    attack_resources_root: str | Path,
) -> Path | None:
    root = Path(attack_resources_root)
    return _resolve_resource_path(
        identifier,
        root,
        search_roots=[shared_ip_root(root), *legacy_resource_roots(protocol, root)],
    )


def _resolve_resource_path(
    identifier: str,
    attack_resources_root: Path,
    *,
    search_roots: Iterable[Path],
) -> Path | None:
    value = str(identifier or "").strip()
    if not value:
        return None

    candidate = Path(value)
    if candidate.is_absolute() and candidate.exists():
        return candidate

    normalized = value.replace("\\", "/")
    direct_candidates: list[Path] = []
    if normalized.startswith("attack_resources/"):
        direct_candidates.append(attack_resources_root / normalized[len("attack_resources/"):])
    elif normalized.startswith("shared/") or normalized.startswith("tcp/") or normalized.startswith("dns/") or normalized.startswith("memcached/") or normalized.startswith("ntp/"):
        direct_candidates.append(attack_resources_root / normalized)

    for path in direct_candidates:
        if path.exists() and path.is_file():
            return path

    filename = Path(normalized).name
    for root in search_roots:
        if not root.exists():
            continue

        exact = root / normalized
        if exact.exists() and exact.is_file():
            return exact

        fallback = root / filename
        if fallback.exists() and fallback.is_file():
            return fallback

        for match in _iter_text_files(root):
            match_id = resource_id_from_path(match, attack_resources_root)
            if normalized in {match_id, match.as_posix(), str(match), match.name}:
                return match

    return None


def _iter_text_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.txt") if path.is_file())


def _normalize_protocols(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, (list, tuple, set)):
        raw_items = list(value)
    else:
        return []

    protocols: list[str] = []
    for item in raw_items:
        normalized = str(item or "").strip().lower()
        if normalized == "all":
            return list(ALL_PROTOCOLS)
        if normalized in ALL_PROTOCOLS and normalized not in protocols:
            protocols.append(normalized)
    return protocols


def _attack_resources_root_from_shared_root(shared_root: Path) -> Path:
    if shared_root.name == "ip_lists" and shared_root.parent.name == "shared":
        return shared_root.parent.parent
    return shared_root.parent


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
