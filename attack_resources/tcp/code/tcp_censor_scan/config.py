from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
import configparser
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


VALID_PKT_METHODS = {"PSH", "PSH_ACK", "SYN", "SYN_PSH_ACK", "SYN_PSH"}
MULTI_PROBE_METHODS = {"SYN_PSH_ACK", "SYN_PSH"}


class ConfigError(ValueError):
    """Raised when a scan configuration is incomplete or invalid."""


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


@dataclass(frozen=True)
class ScanConfig:
    ip_file: Path
    target_host: str
    pkt_method: str
    scan_rate: int = 8000
    result_limit: int = 0
    length_threshold: int = 1000
    geoip_db_path: Path = field(default_factory=lambda: repo_root() / "attack_resources" / "tcp" / "resources" / "geoip" / "GeoLite2-City.mmdb")
    scan_count: int = 1
    ttl: int = 64
    network_interface: str = "eth0"
    output_root: Path = field(default_factory=lambda: repo_root() / "attack_resources" / "tcp" / "runs" / "tcp_censor_scan")
    process_py: Path = field(default_factory=lambda: repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "process_test_3.py")
    ip_take_py: Path = field(default_factory=lambda: repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "IP_take.py")
    magnification_test_py: Path = field(default_factory=lambda: repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "magnification_test_1.py")
    analyze_amplify_log_py: Path = field(default_factory=lambda: repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "analyze_amplify_log.py")
    zmap_root: Path = field(default_factory=lambda: repo_root() / "vendor" / "weaponizing-censors" / "zmap")
    zmap_multiple_probes_root: Path = field(default_factory=lambda: repo_root() / "vendor" / "weaponizing-censors" / "zmap_multiple_probes")
    dry_run: bool = False
    python_bin: str = "python3"

    @property
    def zmap_variant(self) -> str:
        return "multiple_probes" if self.pkt_method in MULTI_PROBE_METHODS else "single_probe"

    @property
    def selected_zmap_root(self) -> Path:
        return self.zmap_multiple_probes_root if self.zmap_variant == "multiple_probes" else self.zmap_root

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key, value in list(data.items()):
            if isinstance(value, Path):
                data[key] = str(value)
        data["zmap_variant"] = self.zmap_variant
        return data


def load_config(path: str | Path) -> ScanConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Config file does not exist: {config_path}")

    if config_path.suffix.lower() == ".ini":
        raw = _load_legacy_ini(config_path)
    else:
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)

    scan = raw.get("scan", {})
    amplify = raw.get("amplify", {})
    paths = raw.get("paths", {})
    scripts = raw.get("scripts", {})
    general = raw.get("general", {})
    zmap = raw.get("zmap", {})

    cfg = ScanConfig(
        ip_file=_path(scan.get("ip_file"), required=True),
        target_host=_string(scan.get("target_host"), "target_host", required=True),
        pkt_method=_string(scan.get("pkt_method"), "pkt_method", required=True),
        scan_rate=_int(scan.get("scan_rate", 8000), "scan_rate", minimum=1),
        result_limit=_int(general.get("result_limit", 0), "result_limit", minimum=0),
        length_threshold=_int(general.get("length_threshold", 1000), "length_threshold", minimum=0),
        geoip_db_path=_path(amplify.get("geoip_db_path", repo_root() / "attack_resources" / "tcp" / "resources" / "geoip" / "GeoLite2-City.mmdb")),
        scan_count=_int(amplify.get("scan_count", 1), "scan_count", minimum=1, maximum=100),
        ttl=_int(amplify.get("ttl", 64), "ttl", minimum=1, maximum=255),
        network_interface=_string(scan.get("network_interface", "eth0"), "network_interface"),
        output_root=_path(paths.get("output_root", repo_root() / "attack_resources" / "tcp" / "runs" / "tcp_censor_scan")),
        process_py=_path(scripts.get("process_py", repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "process_test_3.py")),
        ip_take_py=_path(scripts.get("ip_take_py", repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "IP_take.py")),
        magnification_test_py=_path(scripts.get("magnification_test_py", repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "magnification_test_1.py")),
        analyze_amplify_log_py=_path(scripts.get("analyze_amplify_log_py", repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "analyze_amplify_log.py")),
        zmap_root=_path(zmap.get("single_probe_root", repo_root() / "vendor" / "weaponizing-censors" / "zmap")),
        zmap_multiple_probes_root=_path(zmap.get("multiple_probes_root", repo_root() / "vendor" / "weaponizing-censors" / "zmap_multiple_probes")),
        dry_run=_bool(general.get("dry_run", False), "dry_run"),
        python_bin=_string(general.get("python_bin", "python3"), "python_bin"),
    )
    return validate_config(cfg)


def validate_config(cfg: ScanConfig, check_runtime: bool = True) -> ScanConfig:
    errors: list[str] = []
    if cfg.pkt_method not in VALID_PKT_METHODS:
        errors.append(f"pkt_method must be one of {sorted(VALID_PKT_METHODS)}")
    if not cfg.target_host.strip():
        errors.append("target_host is required")

    required_files = {
        "ip_file": cfg.ip_file,
        "process_py": cfg.process_py,
        "ip_take_py": cfg.ip_take_py,
        "magnification_test_py": cfg.magnification_test_py,
        "analyze_amplify_log_py": cfg.analyze_amplify_log_py,
    }
    if not cfg.dry_run:
        required_files["geoip_db_path"] = cfg.geoip_db_path
    for name, path in required_files.items():
        if not path.exists():
            errors.append(f"{name} does not exist: {path}")

    if check_runtime and not cfg.dry_run and not cfg.selected_zmap_root.exists():
        errors.append(f"selected zmap root does not exist: {cfg.selected_zmap_root}")

    if errors:
        raise ConfigError("; ".join(errors))
    return cfg


def _load_legacy_ini(path: Path) -> dict[str, dict[str, Any]]:
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read(path, encoding="utf-8")
    return {
        "general": {
            "output_root": parser.get(
                "GENERAL_CONFIG",
                "OUTPUT_DIR",
                fallback=str(repo_root() / "attack_resources" / "tcp" / "runs" / "tcp_censor_scan"),
            ),
            "result_limit": parser.get("GENERAL_CONFIG", "RESULT_LIMIT", fallback="0"),
            "length_threshold": parser.get("GENERAL_CONFIG", "LENGTH_THRESHOLD", fallback="1000"),
        },
        "scan": {
            "ip_file": parser.get("SCAN_CONFIG", "IP_FILE", fallback=""),
            "target_host": parser.get("SCAN_CONFIG", "TARGET_HOST", fallback=""),
            "pkt_method": parser.get("SCAN_CONFIG", "PKT_METHOD", fallback=""),
            "scan_rate": parser.get("SCAN_CONFIG", "SCAN_RATE", fallback="8000"),
        },
        "amplify": {
            "geoip_db_path": parser.get("AMPLIFY_CONFIG", "GEOIP_DB_PATH", fallback=str(repo_root() / "attack_resources" / "tcp" / "resources" / "geoip" / "GeoLite2-City.mmdb")),
            "scan_count": parser.get("AMPLIFY_CONFIG", "SCAN_COUNT", fallback="1"),
            "ttl": parser.get("AMPLIFY_CONFIG", "TTL", fallback="64"),
        },
        "scripts": {
            "process_py": parser.get("SCRIPT_CONFIG", "PROCESS_PY", fallback=str(repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "process_test_3.py")),
            "ip_take_py": parser.get("SCRIPT_CONFIG", "IP_TAKE_PY", fallback=str(repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "IP_take.py")),
            "magnification_test_py": parser.get("SCRIPT_CONFIG", "MAGNIFICATION_TEST_PY", fallback=str(repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "magnification_test_1.py")),
            "analyze_amplify_log_py": parser.get("SCRIPT_CONFIG", "ANALYZE_AMPLIFY_LOG_PY", fallback=str(repo_root() / "attack_resources" / "tcp" / "code" / "tcp_censor_scan" / "legacy_scripts" / "analyze_amplify_log.py")),
        },
    }


def _path(value: Any, required: bool = False) -> Path:
    if value is None or str(value).strip() == "":
        if required:
            raise ConfigError("Required path value is missing")
        return Path()
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else repo_root() / path


def _string(value: Any, name: str, required: bool = False) -> str:
    if value is None or str(value).strip() == "":
        if required:
            raise ConfigError(f"{name} is required")
        return ""
    return str(value).strip()


def _int(value: Any, name: str, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if minimum is not None and number < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    if maximum is not None and number > maximum:
        raise ConfigError(f"{name} must be <= {maximum}")
    return number


def _bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise ConfigError(f"{name} must be a boolean")
