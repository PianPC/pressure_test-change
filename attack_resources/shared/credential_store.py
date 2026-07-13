from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

CREDENTIALS_FILE = Path(__file__).resolve().parent / "api_credentials.json"

VALID_SOURCES = {"shodan", "fofa"}


def load_credentials() -> Dict[str, Optional[Dict[str, Any]]]:
    """加载所有凭据。文件不存在或非法时返回 {"shodan": None, "fofa": None}。"""
    if not CREDENTIALS_FILE.exists():
        return {"shodan": None, "fofa": None}
    try:
        with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"shodan": None, "fofa": None}

    if not isinstance(data, dict):
        return {"shodan": None, "fofa": None}

    return {
        "shodan": data.get("shodan") if isinstance(data.get("shodan"), dict) else None,
        "fofa": data.get("fofa") if isinstance(data.get("fofa"), dict) else None,
    }


def get_credentials(source: str) -> Optional[Dict[str, Any]]:
    """返回指定 source 的凭据 dict，未配置返回 None。"""
    if source not in VALID_SOURCES:
        raise ValueError(f"未知的数据源: {source}")
    return load_credentials().get(source)


def save_credentials(source: str, data: Dict[str, Any]) -> None:
    """合并 data（含 updated_at）写入文件，保留其他 source。"""
    if source not in VALID_SOURCES:
        raise ValueError(f"未知的数据源: {source}")
    if not isinstance(data, dict):
        raise ValueError("data 必须是 dict")

    # 读取现有内容（文件不存在/非法时视为空）
    existing: Dict[str, Any] = {"shodan": None, "fofa": None}
    if CREDENTIALS_FILE.exists():
        try:
            with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                existing = loaded
        except (json.JSONDecodeError, OSError):
            pass

    # 合并写入：保留现有字段（如 cookies），用新 data 覆盖/新增
    existing_entry = existing.get(source) if isinstance(existing.get(source), dict) else {}
    merged = dict(existing_entry)
    merged.update(data)
    merged["updated_at"] = datetime.now().isoformat()
    existing[source] = merged

    # 原子写入：先写临时文件再 rename
    tmp_path = CREDENTIALS_FILE.with_suffix(CREDENTIALS_FILE.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, CREDENTIALS_FILE)


def clear_credentials(source: str) -> None:
    """幂等清除指定 source 的凭据。文件不存在时 no-op。"""
    if source not in VALID_SOURCES:
        raise ValueError(f"未知的数据源: {source}")

    if not CREDENTIALS_FILE.exists():
        return

    try:
        with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    if source in data:
        data[source] = None

    tmp_path = CREDENTIALS_FILE.with_suffix(CREDENTIALS_FILE.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, CREDENTIALS_FILE)


def get_cookies(source: str) -> Optional[Dict[str, Any]]:
    """返回指定 source 的 cookies dict，未配置返回 None。"""
    creds = get_credentials(source)
    if not creds:
        return None
    cookies = creds.get("cookies")
    return cookies if isinstance(cookies, dict) else None


def save_cookies(source: str, cookies_dict: Dict[str, Any]) -> None:
    """合并写入 cookies 字段（保留 api_key/email/key 等现有字段）。"""
    if source not in VALID_SOURCES:
        raise ValueError(f"未知的数据源: {source}")
    if not isinstance(cookies_dict, dict):
        raise ValueError("cookies_dict 必须是 dict")
    save_credentials(source, {"cookies": cookies_dict})


def clear_cookies(source: str) -> None:
    """删除指定 source 的 cookies 字段，保留其他字段（api_key/email/key）。"""
    if source not in VALID_SOURCES:
        raise ValueError(f"未知的数据源: {source}")

    if not CREDENTIALS_FILE.exists():
        return

    try:
        with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    entry = data.get(source)
    if isinstance(entry, dict) and "cookies" in entry:
        del entry["cookies"]

    tmp_path = CREDENTIALS_FILE.with_suffix(CREDENTIALS_FILE.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, CREDENTIALS_FILE)
