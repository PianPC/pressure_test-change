from __future__ import annotations

import shutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

file_system_bp = Blueprint("file_system", __name__, url_prefix="/api/files")

# ===== 项目根目录自动识别 =====
# 本地代码环境根目录为 C:\workplace\project\mi4\pressure_test-change，
# 服务器环境根目录为 /home/ppc/pressure_test。两种环境下 app.py 均位于项目根目录，
# 因此以 app.py 所在目录作为项目根，避免依赖运行时 CWD 或绝对路径。
# 所有对外暴露的路径均为相对项目根的相对路径，根目录以上不可见。


def _find_project_root() -> Path:
    """沿本模块向上查找最近的 app.py 所在目录作为项目根目录。"""
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        if (ancestor / "app.py").exists():
            return ancestor
    # 退路：attack_resources/shared/file_system_api.py 上溯两级
    return here.parents[2]


PROJECT_ROOT = _find_project_root()

# 不在文件管理中展示、也不允许访问的目录/文件（git 内部与 Python 缓存）
EXCLUDED_NAMES = {".git", "__pycache__"}

# 文本文件读取上限：超过该大小不回读内容，避免前端加载过大
MAX_TEXT_READ_BYTES = 5 * 1024 * 1024  # 5 MB

# 可作为文本编辑的扩展名（其它扩展名仅可查看、不可在线编辑）
EDITABLE_TEXT_SUFFIXES = {
    ".txt", ".log", ".csv", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".md", ".rst", ".py", ".js", ".ts", ".css", ".html", ".htm", ".xml",
    ".sh", ".bat", ".ps1", ".env", ".gitignore", ".conf", ".properties",
}


def _is_excluded(name: str) -> bool:
    return name in EXCLUDED_NAMES


def _to_rel(path: Path) -> str:
    """把绝对路径转为相对项目根的 POSIX 风格相对路径。根目录返回空串。"""
    try:
        rel = path.relative_to(PROJECT_ROOT)
    except ValueError:
        return ""
    return rel.as_posix()


def _resolve_safe(rel_path: str) -> Path:
    """将相对路径解析到项目根下，并校验未越界。越界或命中排除项则抛出 ValueError。"""
    rel = (rel_path or "").strip()
    # 规范化分隔符并去掉前导分隔
    rel = rel.replace("\\", "/").lstrip("/")
    if not rel or rel == ".":
        return PROJECT_ROOT
    # 逐段校验，禁止 .. 越界和排除项
    parts = rel.split("/")
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("不允许访问项目根目录以上的路径")
        if _is_excluded(part):
            raise ValueError("该路径已被系统排除访问")
    target = (PROJECT_ROOT / rel).resolve()
    # 再次确认最终 realpath 仍在项目根下
    try:
        target.relative_to(PROJECT_ROOT)
    except ValueError:
        raise ValueError("路径超出项目根目录范围")
    return target


def _entry_info(path: Path) -> Optional[Dict[str, Any]]:
    """构造单个目录条目的元信息。被排除项返回 None。"""
    name = path.name
    if _is_excluded(name):
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    is_dir = path.is_dir()
    rel = _to_rel(path)
    entry: Dict[str, Any] = {
        "name": name,
        "path": rel,
        "type": "dir" if is_dir else "file",
        "size": 0 if is_dir else stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    }
    if not is_dir:
        entry["editable"] = _is_editable(path, stat.st_size)
        entry["is_text"] = path.suffix.lower() in EDITABLE_TEXT_SUFFIXES or path.suffix == ""
    return entry


def _is_editable(path: Path, size: int) -> bool:
    if size > MAX_TEXT_READ_BYTES:
        return False
    return path.suffix.lower() in EDITABLE_TEXT_SUFFIXES or path.suffix == ""


def _decode_text(path: Path) -> str:
    """以 UTF-8 读取文本，失败则抛出 ValueError 表示二进制。"""
    with path.open("r", encoding="utf-8") as f:
        return f.read()


@file_system_bp.route("/root", methods=["GET"])
def get_project_root():
    """返回项目根目录名（仅 basename，不含绝对路径），供面包屑展示。"""
    return jsonify({
        "success": True,
        "root": {"name": PROJECT_ROOT.name},
    })


@file_system_bp.route("/tree", methods=["GET"])
def list_tree():
    """列出指定目录下的内容。path 省略时为项目根。"""
    rel = (request.args.get("path") or "").strip()
    try:
        target = _resolve_safe(rel)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if not target.exists():
        return jsonify({"success": False, "message": "路径不存在"}), 404
    if not target.is_dir():
        return jsonify({"success": False, "message": "目标不是目录"}), 400

    dirs: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    try:
        for child in sorted(target.iterdir(), key=lambda p: p.name.lower()):
            info = _entry_info(child)
            if info is None:
                continue
            (dirs if info["type"] == "dir" else files).append(info)
    except OSError as exc:
        return jsonify({"success": False, "message": f"读取目录失败: {exc}"}), 500

    return jsonify({
        "success": True,
        "path": _to_rel(target),
        "entries": dirs + files,
    })


@file_system_bp.route("/file", methods=["GET"])
def read_file():
    """读取文件内容。二进制或超大文件只返回元信息。"""
    rel = (request.args.get("path") or "").strip()
    try:
        target = _resolve_safe(rel)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if not target.exists():
        return jsonify({"success": False, "message": "文件不存在"}), 404
    if target.is_dir():
        return jsonify({"success": False, "message": "目标是一个目录"}), 400

    try:
        stat = target.stat()
    except OSError as exc:
        return jsonify({"success": False, "message": f"读取文件信息失败: {exc}"}), 500

    file_info: Dict[str, Any] = {
        "name": target.name,
        "path": _to_rel(target),
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "editable": False,
        "encoding": "binary",
        "content": "",
    }

    if stat.st_size > MAX_TEXT_READ_BYTES:
        file_info["encoding"] = "too_large"
        return jsonify({"success": True, "file": file_info})

    # 尝试以文本读取
    try:
        content = _decode_text(target)
    except UnicodeDecodeError:
        file_info["encoding"] = "binary"
        file_info["editable"] = False
        return jsonify({"success": True, "file": file_info})
    except OSError as exc:
        return jsonify({"success": False, "message": f"读取文件失败: {exc}"}), 500

    file_info["encoding"] = "text"
    file_info["content"] = content
    file_info["editable"] = _is_editable(target, stat.st_size)
    return jsonify({"success": True, "file": file_info})


@file_system_bp.route("/file", methods=["PUT"])
def update_file():
    """更新已存在的文件内容。"""
    rel = (request.args.get("path") or "").strip()
    try:
        target = _resolve_safe(rel)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if not target.exists() or not target.is_file():
        return jsonify({"success": False, "message": "文件不存在"}), 404

    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    if not isinstance(content, str):
        return jsonify({"success": False, "message": "content 必须是字符串"}), 400

    try:
        normalized = content.replace("\r\n", "\n")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as f:
            f.write(normalized)
    except OSError as exc:
        logger.error("写入文件失败: %s", exc, exc_info=True)
        return jsonify({"success": False, "message": f"写入失败: {exc}"}), 500

    stat = target.stat()
    return jsonify({
        "success": True,
        "message": "已保存",
        "file": {
            "name": target.name,
            "path": _to_rel(target),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        },
    })


@file_system_bp.route("/file", methods=["POST"])
def create_item():
    """创建文件或目录。body: { path, type, content? }"""
    data = request.get_json(silent=True) or {}
    rel = (data.get("path") or "").strip()
    item_type = (data.get("type") or "file").strip().lower()
    if not rel:
        return jsonify({"success": False, "message": "缺少路径"}), 400
    if item_type not in ("file", "dir"):
        return jsonify({"success": False, "message": "type 必须是 file 或 dir"}), 400

    # 防止在根目录直接覆盖 app.py 等顶层文件时意外破坏，仍允许创建但校验名规范
    name = rel.replace("\\", "/").rstrip("/").split("/")[-1]
    if not name:
        return jsonify({"success": False, "message": "文件名不能为空"}), 400

    try:
        target = _resolve_safe(rel)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if target.exists():
        return jsonify({"success": False, "message": f"{name} 已存在"}), 409

    try:
        if item_type == "dir":
            target.mkdir(parents=True, exist_ok=False)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            content = data.get("content", "")
            if content is None:
                content = ""
            if not isinstance(content, str):
                return jsonify({"success": False, "message": "content 必须是字符串"}), 400
            target.write_text(content, encoding="utf-8")
    except OSError as exc:
        logger.error("创建失败: %s", exc, exc_info=True)
        return jsonify({"success": False, "message": f"创建失败: {exc}"}), 500

    return jsonify({
        "success": True,
        "message": f"已创建 {('目录' if item_type == 'dir' else '文件')} {name}",
        "item": {
            "name": name,
            "path": _to_rel(target),
            "type": item_type,
        },
    })


@file_system_bp.route("/file", methods=["DELETE"])
def delete_item():
    """删除文件或目录（目录递归删除）。"""
    rel = (request.args.get("path") or "").strip()
    try:
        target = _resolve_safe(rel)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if not target.exists():
        return jsonify({"success": False, "message": "路径不存在"}), 404
    # 不允许直接删除项目根目录
    if target == PROJECT_ROOT:
        return jsonify({"success": False, "message": "不允许删除项目根目录"}), 400

    try:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    except OSError as exc:
        logger.error("删除失败: %s", exc, exc_info=True)
        return jsonify({"success": False, "message": f"删除失败: {exc}"}), 500

    return jsonify({"success": True, "message": f"已删除 {target.name}"})


@file_system_bp.route("/rename", methods=["POST"])
def rename_item():
    """重命名 / 移动。body: { path, new_path }"""
    data = request.get_json(silent=True) or {}
    rel = (data.get("path") or "").strip()
    new_rel = (data.get("new_path") or "").strip()
    if not rel or not new_rel:
        return jsonify({"success": False, "message": "缺少 path 或 new_path"}), 400

    try:
        src = _resolve_safe(rel)
        dst = _resolve_safe(new_rel)
    except ValueError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    if not src.exists():
        return jsonify({"success": False, "message": "源路径不存在"}), 404
    if src == PROJECT_ROOT:
        return jsonify({"success": False, "message": "不允许重命名项目根目录"}), 400
    if dst.exists():
        return jsonify({"success": False, "message": "目标路径已存在"}), 409

    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
    except OSError as exc:
        logger.error("重命名失败: %s", exc, exc_info=True)
        return jsonify({"success": False, "message": f"重命名失败: {exc}"}), 500

    return jsonify({
        "success": True,
        "message": "已重命名",
        "item": {
            "name": dst.name,
            "path": _to_rel(dst),
            "type": "dir" if dst.is_dir() else "file",
        },
    })


@file_system_bp.errorhandler(400)
def _bad_request(error):
    return jsonify({"success": False, "message": "请求参数无效"}), 400
