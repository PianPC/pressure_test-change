from __future__ import annotations

import logging

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
import csv
import os
import platform
import stat
import time
import shutil
import signal
import subprocess
import sys

from .config import ScanConfig, load_config, repo_root
from .metadata import now_iso, read_metadata, update_stage, write_metadata


logger = logging.getLogger(__name__)


TCP_FLAG_MAP = {
    "PSH": "TH_PUSH",
    "PSH_ACK": "TH_PUSH | TH_ACK",
    "SYN": "TH_SYN",
    "SYN_PSH_ACK": "TH_PUSH | TH_ACK",
    "SYN_PSH": "TH_PUSH",
}


def run_pipeline(config: ScanConfig | str | Path, run_dir: Path | None = None) -> dict[str, Any]:
    cfg = load_config(config) if not isinstance(config, ScanConfig) else config
    run_dir = run_dir or _prepare_run(cfg)
    log_path = run_dir / "pipeline.log"
    artifacts = _artifact_paths(cfg, run_dir)

    with _pipeline_log(log_path) as log:
        log(f"Run directory: {run_dir}")
        log(f"Mode: {'dry-run' if cfg.dry_run else 'real'}")
        try:
            zmap_workdir = prepare_zmap(cfg, run_dir, log)
            run_zmap_scan(cfg, run_dir, zmap_workdir, artifacts, log)
            process_scan_csv(cfg, run_dir, artifacts, log)
            extract_ips(cfg, run_dir, artifacts, log)
            run_amplification_test(cfg, run_dir, artifacts, log)
            analyze_amplification_log(cfg, run_dir, artifacts, log)
            extract_qualified_ips(cfg, run_dir, artifacts, log)
        except Exception as exc:
            metadata = read_metadata(run_dir)
            current_stage = metadata.get("current_stage")
            if current_stage:
                update_stage(run_dir, current_stage, "failed", error=str(exc))
                metadata = read_metadata(run_dir)
            metadata["status"] = "failed"
            metadata["ended_at"] = now_iso()
            metadata["error"] = str(exc)
            metadata["current_stage"] = None
            write_metadata(run_dir, metadata)
            log(f"FAILED: {exc}")
            _cleanup_if_requested(run_dir)
            _cleanup_work_dir(run_dir)
            raise

    metadata = read_metadata(run_dir)
    metadata["status"] = "completed"
    metadata["ended_at"] = now_iso()
    metadata["current_stage"] = None
    write_metadata(run_dir, metadata)
    _cleanup_if_requested(run_dir)
    _cleanup_work_dir(run_dir)
    return metadata


def stop_run(run_id: str, output_root: str | Path | None = None, cleanup: bool = False) -> bool:
    root = Path(output_root) if output_root else repo_root() / "runs"
    run_dir = root / run_id
    stopped = False
    for pid_file in run_dir.glob("*.pid"):
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGINT)
            stopped = True
        except (OSError, ValueError):
            continue
    if stopped:
        metadata = read_metadata(run_dir)
        metadata["status"] = "stopping"
        metadata["stop_requested"] = True
        metadata["cleanup_requested"] = cleanup
        write_metadata(run_dir, metadata)
    return stopped


def prepare_zmap(cfg: ScanConfig, run_dir: Path, log) -> Path:
    update_stage(run_dir, "prepare_zmap", "running")
    if cfg.dry_run:
        update_stage(run_dir, "prepare_zmap", "skipped", reason="dry_run")
        return cfg.selected_zmap_root

    # The forbidden_scan probe module reads host/flags at runtime via
    # --probe-args, so the shared pre-built zmap binary is used directly
    # and no per-run source copy is needed.
    zmap_bin = cfg.selected_zmap_root / "src" / "zmap"
    if not _ensure_executable(zmap_bin):
        raise FileNotFoundError(f"zmap executable not available: {zmap_bin}. Build zmap before running real scans.")
    probe_args = f"host={cfg.target_host},flags={TCP_FLAG_MAP[cfg.pkt_method]}"
    log(f"Using shared zmap build: {cfg.selected_zmap_root}")
    log(f"Probe args: {probe_args}")
    update_stage(run_dir, "prepare_zmap", "completed", workdir=str(cfg.selected_zmap_root), probe_args=probe_args)
    return cfg.selected_zmap_root


def run_zmap_scan(cfg: ScanConfig, run_dir: Path, zmap_workdir: Path, artifacts: dict[str, Path], log) -> None:
    update_stage(run_dir, "run_zmap_scan", "running")
    if cfg.dry_run:
        _write_mock_scan_csv(artifacts["raw_csv"])
        artifacts["scan_log"].write_text("dry_run: zmap scan skipped\n", encoding="utf-8")
        update_stage(run_dir, "run_zmap_scan", "completed", dry_run=True)
        _save_artifacts(run_dir, artifacts)
        return

    zmap_bin = zmap_workdir / "src" / "zmap"
    if not _ensure_executable(zmap_bin):
        raise FileNotFoundError(f"zmap executable not available: {zmap_bin}. Build zmap before running real scans.")

    command = [
        str(zmap_bin),
        "-M", "forbidden_scan",
        "-p", "80",
        "-i", cfg.network_interface,
        "-w", str(cfg.ip_file),
        "-o", str(artifacts["raw_csv"]),
        "-f", "saddr,len,payloadlen,flags",
        "--output-module=csv",
        f"--rate={cfg.scan_rate}",
        f"--probe-args=host={cfg.target_host},flags={TCP_FLAG_MAP[cfg.pkt_method]}",
    ]
    log("Running zmap: " + " ".join(command))
    # zmap 扫描超时：默认 5 分钟，避免因网络或权限问题无限阻塞
    _run_command(command, zmap_workdir, artifacts["scan_log"], run_dir / "zmap.pid", timeout=300)
    update_stage(run_dir, "run_zmap_scan", "completed")
    _save_artifacts(run_dir, artifacts)


def process_scan_csv(cfg: ScanConfig, run_dir: Path, artifacts: dict[str, Path], log) -> None:
    update_stage(run_dir, "process_scan_csv", "running")
    if cfg.dry_run:
        log("Processing mock scan CSV")
        _process_mock_scan_csv(artifacts["raw_csv"], artifacts["processed_csv"], cfg.result_limit, cfg.length_threshold)
        artifacts["process_log"].write_text(
            "dry_run: processed mock scan CSV without legacy script\n",
            encoding="utf-8",
        )
        update_stage(run_dir, "process_scan_csv", "completed", dry_run=True)
        _save_artifacts(run_dir, artifacts)
        return

    command = [
        cfg.python_bin,
        str(cfg.process_py),
        str(artifacts["raw_csv"]),
        str(artifacts["processed_csv"]),
        str(cfg.result_limit),
        str(cfg.length_threshold),
    ]
    log("Processing scan CSV")
    _run_command(command, run_dir, artifacts["process_log"], run_dir / "process.pid")
    update_stage(run_dir, "process_scan_csv", "completed")
    _save_artifacts(run_dir, artifacts)


def extract_ips(cfg: ScanConfig, run_dir: Path, artifacts: dict[str, Path], log) -> None:
    update_stage(run_dir, "extract_ips", "running")
    if cfg.dry_run:
        log("Extracting mock IP list")
        ips = _extract_ips_from_processed_csv(artifacts["processed_csv"], artifacts["ip_txt"])
        artifacts["ip_take_log"].write_text(
            f"dry_run: extracted {len(ips)} unique IP(s) without legacy script\n",
            encoding="utf-8",
        )
        update_stage(run_dir, "extract_ips", "completed", dry_run=True)
        _save_artifacts(run_dir, artifacts)
        return

    command = [cfg.python_bin, str(cfg.ip_take_py), str(artifacts["processed_csv"]), str(artifacts["ip_txt"])]
    log("Extracting IP list")
    _run_command(command, run_dir, artifacts["ip_take_log"], run_dir / "ip_take.pid")
    update_stage(run_dir, "extract_ips", "completed")
    _save_artifacts(run_dir, artifacts)


def run_amplification_test(cfg: ScanConfig, run_dir: Path, artifacts: dict[str, Path], log) -> None:
    update_stage(run_dir, "run_amplification_test", "running")
    if cfg.dry_run:
        ips = _read_ip_list(artifacts["ip_txt"])
        _write_mock_amplification_log(cfg, artifacts["amplification_log"], ips)
        artifacts["amplification_stdout"].write_text("dry_run: amplification test skipped\n", encoding="utf-8")
        update_stage(run_dir, "run_amplification_test", "completed", dry_run=True)
        _save_artifacts(run_dir, artifacts)
        return

    payload = f"GET / HTTP/1.1\\r\\nHost: {cfg.target_host}\\r\\nUser-Agent: Mozilla/5.0\\r\\nConnection: close\\r\\n\\r\\n"
    command = [
        cfg.python_bin,
        str(cfg.magnification_test_py),
        str(artifacts["ip_txt"]),
        payload,
        str(artifacts["amplification_log"]),
        cfg.pkt_method,
        str(cfg.ttl),
        str(cfg.scan_count),
    ]
    log("Running amplification test")
    _run_command(command, run_dir, artifacts["amplification_stdout"], run_dir / "amplification.pid")
    update_stage(run_dir, "run_amplification_test", "completed")
    _save_artifacts(run_dir, artifacts)


def analyze_amplification_log(cfg: ScanConfig, run_dir: Path, artifacts: dict[str, Path], log) -> None:
    update_stage(run_dir, "analyze_amplification_log", "running")
    if cfg.dry_run:
        log("Writing mock amplification analysis")
        ips = _read_ip_list(artifacts["ip_txt"])
        _write_mock_analysis_report(cfg, artifacts["amplification_log"], artifacts["analysis_report"], ips)
        artifacts["analysis_stdout"].write_text(
            "dry_run: generated mock analysis report without legacy script\n",
            encoding="utf-8",
        )
        update_stage(run_dir, "analyze_amplification_log", "completed", dry_run=True)
        _save_artifacts(run_dir, artifacts)
        return

    command = [
        cfg.python_bin,
        str(cfg.analyze_amplify_log_py),
        str(artifacts["amplification_log"]),
        str(artifacts["analysis_report"]),
    ]
    log("Analyzing amplification log")
    _run_command(command, run_dir, artifacts["analysis_stdout"], run_dir / "analysis.pid")
    update_stage(run_dir, "analyze_amplification_log", "completed")
    _save_artifacts(run_dir, artifacts)


def extract_qualified_ips(cfg: ScanConfig, run_dir: Path, artifacts: dict[str, Path], log) -> None:
    update_stage(run_dir, "extract_qualified_ips", "running")
    min_ratio = cfg.min_amplification
    min_success_rate = cfg.min_success_rate
    max_cv = cfg.max_cv  # 最大变异系数（默认1.5）

    if cfg.dry_run:
        log("Writing mock qualified IPs")
        ips = _read_ip_list(artifacts["ip_txt"])
        qualified = []
        for ip in ips[:3]:
            qualified.append({
                "ip": ip,
                "median_ratio": min_ratio + 1.0,
                "avg_ratio": min_ratio + 1.0,
                "success_rate": 100.0,
                "cv": 0.0,
            })
        _write_qualified_ips(artifacts["qualified_ips"], qualified, min_ratio, min_success_rate, max_cv)
        artifacts["qualified_log"].write_text(
            f"dry_run: extracted {len(qualified)} qualified IPs (min_ratio={min_ratio}, min_success_rate={min_success_rate}%, max_cv={max_cv})\n",
            encoding="utf-8",
        )
        update_stage(run_dir, "extract_qualified_ips", "completed", dry_run=True)
        _save_artifacts(run_dir, artifacts)
        return

    qualified = _parse_amplification_log_for_qualified(
        artifacts["amplification_log"],
        min_ratio=min_ratio,
        min_success_rate=min_success_rate,
        scan_count=cfg.scan_count,
        max_cv=max_cv,
    )
    _write_qualified_ips(artifacts["qualified_ips"], qualified, min_ratio, min_success_rate, max_cv)

    log(f"Extracted {len(qualified)} qualified IPs with median amplification >= {min_ratio}, success_rate >= {min_success_rate}%, and CV <= {max_cv}")
    artifacts["qualified_log"].write_text(
        f"Extracted {len(qualified)} qualified IPs from amplification log\n"
        f"Median amplification ratio >= {min_ratio}\n"
        f"Min success rate: {min_success_rate}%\n"
        f"Max coefficient of variation (CV): {max_cv}\n",
        encoding="utf-8",
    )

    update_stage(run_dir, "extract_qualified_ips", "completed")
    _save_artifacts(run_dir, artifacts)


def _parse_amplification_log_for_qualified(
    log_path: Path,
    min_ratio: float,
    min_success_rate: float,
    scan_count: int,
    max_cv: float = 1.5,
) -> list[dict[str, Any]]:
    import math

    def _median(values: list[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        mid = n // 2
        if n % 2 == 1:
            return float(sorted_vals[mid])
        return (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0

    def _stddev(values: list[float], avg: float) -> float:
        if len(values) < 2:
            return 0.0
        variance = sum((v - avg) ** 2 for v in values) / (len(values) - 1)
        return math.sqrt(variance)

    qualified = []
    if not log_path.exists():
        return qualified

    current_ip = None
    ratios = []
    # success_rate 归一化分母，避免 scan_count 为 0 时除零
    norm_count = max(scan_count, 1)

    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            ip_match = _extract_ip_from_line(line)
            if ip_match:
                if current_ip and ratios:
                    avg_ratio = sum(ratios) / len(ratios)
                    median_ratio = _median(ratios)
                    std_dev = _stddev(ratios, avg_ratio)
                    cv = (std_dev / avg_ratio) if avg_ratio > 0 else 0.0
                    success_rate = round(len(ratios) / norm_count * 100, 1)
                    # 双阈值筛选：成功率 + 中位数放大率 + 变异系数稳定性
                    if (
                        success_rate >= min_success_rate
                        and median_ratio >= min_ratio
                        and cv <= max_cv
                    ):
                        qualified.append({
                            "ip": current_ip,
                            "median_ratio": round(median_ratio, 2),
                            "avg_ratio": round(avg_ratio, 2),
                            "std_dev": round(std_dev, 2),
                            "cv": round(cv, 2),
                            "success_rate": success_rate,
                            "samples": len(ratios),
                        })
                current_ip = ip_match
                ratios = []
                continue

            ratio_match = _extract_ratio_from_line(line)
            if ratio_match and current_ip:
                ratios.append(ratio_match)

        if current_ip and ratios:
            avg_ratio = sum(ratios) / len(ratios)
            median_ratio = _median(ratios)
            std_dev = _stddev(ratios, avg_ratio)
            cv = (std_dev / avg_ratio) if avg_ratio > 0 else 0.0
            success_rate = round(len(ratios) / norm_count * 100, 1)
            if (
                success_rate >= min_success_rate
                and median_ratio >= min_ratio
                and cv <= max_cv
            ):
                qualified.append({
                    "ip": current_ip,
                    "median_ratio": round(median_ratio, 2),
                    "avg_ratio": round(avg_ratio, 2),
                    "std_dev": round(std_dev, 2),
                    "cv": round(cv, 2),
                    "success_rate": success_rate,
                    "samples": len(ratios),
                })

    # 按中位数放大率降序排序（中位数比平均值更抗极端值）
    qualified.sort(key=lambda x: x["median_ratio"], reverse=True)
    return qualified


def _extract_ip_from_line(line: str) -> str | None:
    import re
    # 匹配 magnification_test_1.py 输出的 "==== ... 测试IP：1.2.3.4（国家） ===="
    # 必须带 ==== 前缀，避免误匹配 traceroute 路径中的 IP
    match = re.search(r"====.*?测试IP：([\d.]+)", line)
    if match:
        return match.group(1)
    return None


def _extract_ratio_from_line(line: str) -> float | None:
    import re
    # 匹配 magnification_test_1.py 输出的 "📊 放大比率：1.23（接收/发送）"
    match = re.search(r"放大比率：([\d.]+)", line)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return None


def _write_qualified_ips(
    output_path: Path,
    qualified: list[dict[str, Any]],
    min_ratio: float,
    min_success_rate: float,
    max_cv: float,
) -> None:
    lines = [
        f"# TCP优质反射器IP列表（中位数放大率 >= {min_ratio}x，成功率 >= {min_success_rate}%，变异系数CV <= {max_cv}）",
        f"# 生成时间: {now_iso()}",
        f"# 优质IP数量: {len(qualified)}",
        "",
    ]
    for item in qualified:
        # 每行只写纯 IP，与 DNS/NTP/Memcached 对齐
        lines.append(item["ip"])

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def prepare_run(cfg: ScanConfig) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{timestamp}_{cfg.ip_file.stem}_{cfg.pkt_method}_{_safe_host(cfg.target_host)}"
    run_dir = cfg.output_root / run_id
    suffix = 1
    while run_dir.exists():
        suffix += 1
        run_dir = cfg.output_root / f"{run_id}_{suffix}"
    run_dir.mkdir(parents=True)
    metadata = {
        "run_id": run_dir.name,
        "status": "running",
        "started_at": now_iso(),
        "run_dir": str(run_dir),
        "config": cfg.to_dict(),
        "stages": {},
        "artifacts": {},
        "current_stage": None,
        "error": "",
        "stop_requested": False,
        "cleanup_requested": False,
    }
    write_metadata(run_dir, metadata)
    return run_dir


def _prepare_run(cfg: ScanConfig) -> Path:
    return prepare_run(cfg)


def _artifact_paths(cfg: ScanConfig, run_dir: Path) -> dict[str, Path]:
    ip_prefix = cfg.ip_file.stem[:2] or "ip"
    host_suffix = _safe_host(cfg.target_host)[:2] or "host"
    stem = f"{ip_prefix}-{cfg.pkt_method}-{host_suffix}"
    return {
        "raw_csv": run_dir / f"{stem}.csv",
        "processed_csv": run_dir / f"{stem}_processed.csv",
        "ip_txt": run_dir / f"{stem}-IPs.txt",
        "scan_log": run_dir / f"{cfg.pkt_method}_zmap_scan_details.log",
        "process_log": run_dir / "process_csv.log",
        "ip_take_log": run_dir / "extract_ips.log",
        "amplification_log": run_dir / f"amplification_test_{cfg.pkt_method}.log",
        "amplification_stdout": run_dir / f"magnification_test_stdout_stderr_{cfg.pkt_method}.log",
        "analysis_report": run_dir / f"amplification_analysis_report_{cfg.pkt_method}.txt",
        "analysis_stdout": run_dir / "analysis_stdout_stderr.log",
        "qualified_ips": run_dir / "qualified_ips.txt",
        "qualified_log": run_dir / "extract_qualified_ips.log",
    }


def _save_artifacts(run_dir: Path, artifacts: dict[str, Path]) -> None:
    metadata = read_metadata(run_dir)
    metadata["artifacts"] = {name: str(path) for name, path in artifacts.items()}
    write_metadata(run_dir, metadata)


def _cleanup_work_dir(run_dir: Path) -> None:
    # Remove the per-run isolated zmap work dir left behind by older
    # pipeline versions (no longer created since probe-args support).
    shutil.rmtree(run_dir / "work", ignore_errors=True)


def _run_command(command: list[str], cwd: Path, log_file: Path, pid_file: Path, timeout: int | None = None) -> None:
    if command and command[0] in {"python", "python3"}:
        command = [sys.executable, *command[1:]]
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    # 使用行缓冲写入日志，确保子进程输出能及时落盘
    with log_file.open("w", encoding="utf-8", errors="replace", buffering=1) as fh:
        process = subprocess.Popen(command, cwd=str(cwd), stdout=fh, stderr=subprocess.STDOUT, text=True, env=env, bufsize=1)
        pid_file.write_text(str(process.pid), encoding="utf-8")
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return_code = -1
    try:
        pid_file.unlink()
    except FileNotFoundError:
        pass
    if return_code != 0:
        cmd_str = ' '.join(command)
        hint = ""
        if "zmap" in cmd_str and not os.geteuid() == 0:
            hint = "（zmap 需要 root 权限运行原始报文发送，请使用 sudo 启动）"
        raise RuntimeError(
            f"Command failed with exit code {return_code}: {cmd_str}. "
            f"See log: {log_file} {hint}"
        )


def cleanup_run_artifacts(run_id: str, output_root: str | Path | None = None) -> bool:
    root = Path(output_root) if output_root else repo_root() / "runs"
    run_dir = root / run_id
    if not run_dir.exists():
        return False
    shutil.rmtree(run_dir)
    return True


def _cleanup_if_requested(run_dir: Path) -> None:
    metadata = read_metadata(run_dir)
    if metadata.get("cleanup_requested"):
        shutil.rmtree(run_dir, ignore_errors=True)


def preflight_check(cfg: ScanConfig) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(_check_path("ip_file", cfg.ip_file, "IP 资源文件"))
    checks.append(_check_path("process_py", cfg.process_py, "CSV 处理脚本"))
    checks.append(_check_path("ip_take_py", cfg.ip_take_py, "IP 提取脚本"))
    checks.append(_check_path("magnification_test_py", cfg.magnification_test_py, "放大测试脚本"))
    checks.append(_check_path("analyze_amplify_log_py", cfg.analyze_amplify_log_py, "分析脚本"))
    checks.append(_check_python(cfg.python_bin))
    checks.append(_check_interface(cfg.network_interface))
    if not cfg.dry_run:
        checks.append(_check_path("geoip_db_path", cfg.geoip_db_path, "GeoIP 数据库"))
        checks.extend(_check_python_modules(cfg.python_bin, ["geoip2", "scapy", "numpy"]))
        checks.append(_check_command("traceroute"))
        checks.append(_check_path("selected_zmap_root", cfg.selected_zmap_root, "ZMap 源码目录"))
        checks.append(_check_zmap_binary(cfg.selected_zmap_root))
        checks.append(_check_root_privilege())
    return {
        "ok": all(item["ok"] for item in checks),
        "dry_run": cfg.dry_run,
        "pkt_method": cfg.pkt_method,
        "checks": checks,
        "hints": _preflight_hints(cfg),
    }


def _check_path(key: str, path: Path, label: str) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "ok": path.exists(),
        "path": str(path),
        "message": f"{label}存在" if path.exists() else f"{label}不存在",
    }


def _check_root_privilege() -> dict[str, Any]:
    """检查是否具备 root 权限（zmap 真实扫描需要）。"""
    is_root = os.geteuid() == 0
    return {
        "key": "root_privilege",
        "label": "Root 权限（zmap 真实扫描必备）",
        "ok": is_root,
        "path": "当前用户" if is_root else "当前用户（非 root）",
        "message": "具备 root 权限" if is_root else "缺少 root 权限，真实扫描需要使用 sudo 启动",
    }


def _check_python(python_bin: str) -> dict[str, Any]:
    resolved = shutil.which(python_bin) if python_bin else None
    return {
        "key": "python_bin",
        "label": "Python 解释器",
        "ok": bool(resolved or python_bin in {"python", "python3"}),
        "path": resolved or python_bin,
        "message": "Python 可用" if (resolved or python_bin in {"python", "python3"}) else "Python 不可用",
    }


def _check_python_modules(python_bin: str, modules: list[str]) -> list[dict[str, Any]]:
    return [_check_python_module(python_bin, module) for module in modules]


def _check_python_module(python_bin: str, module: str) -> dict[str, Any]:
    command = [python_bin, "-c", f"import {module}"]
    if python_bin in {"python", "python3"}:
        command[0] = sys.executable
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        ok = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    return {
        "key": f"python_module_{module}",
        "label": f"Python 模块 {module}",
        "ok": ok,
        "path": python_bin,
        "message": f"{module} 可导入" if ok else f"{module} 未安装或不可导入",
    }


def _check_command(name: str) -> dict[str, Any]:
    resolved = shutil.which(name)
    return {
        "key": f"command_{name}",
        "label": f"系统命令 {name}",
        "ok": bool(resolved),
        "path": resolved or name,
        "message": f"{name} 可用" if resolved else f"{name} 不可用",
    }


def _check_interface(name: str) -> dict[str, Any]:
    ok = bool(name.strip())
    message = "网卡名称已提供"
    if platform.system().lower().startswith("linux"):
        ok = ok and Path("/sys/class/net", name).exists()
        message = "网卡存在" if ok else "网卡不存在"
    return {
        "key": "network_interface",
        "label": "网卡接口",
        "ok": ok,
        "path": name,
        "message": message,
    }


def _check_zmap_binary(zmap_root: Path) -> dict[str, Any]:
    zmap_bin = zmap_root / "src" / "zmap"
    executable = _ensure_executable(zmap_bin)
    return {
        "key": "zmap_binary",
        "label": "ZMap 可执行文件",
        "ok": executable,
        "path": str(zmap_bin),
        "message": "ZMap 可执行文件可用" if executable else "ZMap 可执行文件不可用",
    }


def _ensure_executable(path: Path) -> bool:
    if not path.exists():
        return False
    if os.access(path, os.X_OK):
        return True
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        return False
    return os.access(path, os.X_OK)


def _preflight_hints(cfg: ScanConfig) -> list[str]:
    hints = [
        f"当前报文方法: {cfg.pkt_method}",
        f"当前网卡接口: {cfg.network_interface}",
    ]
    if not cfg.dry_run:
        hints.append("真实扫描需要 ZMap 可执行文件、可用网卡，以及具备原始报文发送能力的运行环境。")
    return hints


def _write_mock_scan_csv(path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["saddr", "len", "payloadlen", "flags"])
        writer.writeheader()
        writer.writerow({"saddr": "192.0.2.1", "len": "2500", "payloadlen": "2400", "flags": "PA"})
        writer.writerow({"saddr": "192.0.2.1", "len": "100", "payloadlen": "60", "flags": "PA"})
        writer.writerow({"saddr": "198.51.100.2", "len": "1200", "payloadlen": "1000", "flags": "R"})


def _process_mock_scan_csv(input_path: Path, output_path: Path, limit_count: int, length_threshold: int) -> None:
    summaries: dict[str, dict[str, Any]] = {}
    with input_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            saddr = (row.get("saddr") or "").strip()
            if not saddr:
                continue
            summary = summaries.setdefault(
                saddr,
                {"len": 0, "payloadlen": 0, "flags": set(), "count": 0},
            )
            summary["len"] += _safe_int(row.get("len"))
            summary["payloadlen"] += _safe_int(row.get("payloadlen"))
            summary["count"] += 1
            flag = (row.get("flags") or "").strip()
            if flag:
                summary["flags"].add(flag)

    rows = [_mock_summary_row(saddr, summary) for saddr, summary in summaries.items() if summary["len"] > length_threshold]
    if not rows:
        rows = [_mock_summary_row(saddr, summary) for saddr, summary in summaries.items()]

    rows.sort(key=lambda item: item["len"], reverse=True)
    if limit_count > 0:
        rows = rows[:limit_count]

    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["saddr", "len", "payloadlen", "flags", "count"])
        writer.writeheader()
        writer.writerows(rows)


def _mock_summary_row(saddr: str, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "saddr": saddr,
        "len": summary["len"],
        "payloadlen": summary["payloadlen"],
        "flags": ",".join(sorted(summary["flags"])),
        "count": summary["count"],
    }


def _extract_ips_from_processed_csv(input_path: Path, output_path: Path) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    with input_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            ip = (row.get("saddr") or "").strip()
            if ip and ip not in seen:
                ips.append(ip)
                seen.add(ip)

    output_path.write_text("".join(f"{ip}\n" for ip in ips), encoding="utf-8")
    return ips


def _read_ip_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _write_mock_amplification_log(cfg: ScanConfig, path: Path, ips: list[str]) -> None:
    # 模拟 magnification_test_1.py 的真实中文日志格式，确保 dry_run 能测试解析逻辑
    from datetime import datetime
    lines = [
        f"dry_run 模拟日志 | pkt_method={cfg.pkt_method} | target={cfg.target_host} | ttl={cfg.ttl} | scan_count={cfg.scan_count}",
        "",
    ]
    if not ips:
        lines.append("无候选 IP")
    for ip in ips:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # 模拟 scan_count 次扫描，每次都有响应（放大率 4.64 与真实样本一致）
        lines.append(f"==== {ts} | 测试IP：{ip}（Example） | 扫描次数：{cfg.scan_count} ====")
        for i in range(cfg.scan_count):
            lines.append(f"--- 第{i+1}/{cfg.scan_count}次扫描 ---")
            lines.append(f"📤 发送数据包：1个 | 总发送大小：130 bytes")
            lines.append(f"📥 收到响应：1个 | 总接收大小：603 bytes")
            lines.append(f"📊 放大比率：4.64（接收/发送）")
        lines.append(f"--- 该IP扫描完成 | 成功响应：{cfg.scan_count}/{cfg.scan_count}次 ---")
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_mock_analysis_report(cfg: ScanConfig, log_path: Path, report_path: Path, ips: list[str]) -> None:
    lines = [
        "TCP amplification analysis report (dry_run)",
        "=" * 48,
        f"generated_at: {now_iso()}",
        f"source_log: {log_path}",
        f"target_host: {cfg.target_host}",
        f"pkt_method: {cfg.pkt_method}",
        f"ttl: {cfg.ttl}",
        f"scan_count: {cfg.scan_count}",
        "",
        "ranking",
        "-" * 48,
    ]
    if not ips:
        lines.append("No candidate IPs were available for dry_run analysis.")
    for rank, ip in enumerate(ips, start=1):
        lines.append(f"{rank}. {ip} | avg_ratio=1.00 | success_rate=100.0% | samples=1")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_host(host: str) -> str:
    cleaned = host.removeprefix("www.")
    return "".join(ch if ch.isalnum() else "_" for ch in cleaned).strip("_") or "target"


@contextmanager
def _pipeline_log(path: Path) -> Iterator[Any]:
    def log(message: str) -> None:
        line = f"[{now_iso()}] {message}"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        logger.info(line)

    yield log
