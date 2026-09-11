"""部署冒烟测试（Python 版，对应 scripts/smoke_test.sh）。

只读 API 检查，不发起任何攻击流量。用 ``requests`` 向当前服务的
``base_url`` 发 HTTP 请求，覆盖 scripts/smoke_test.sh 的全部端点。

判断分级（与 shell 版一致）：

* ``pass`` — HTTP 200 且 ``success`` 为 true（或仅断言 200 的端点）
* ``warn`` — API 正常但返回数据为空（指定了 nonempty_kw 却未命中）
* ``fail`` — HTTP 非 200 / 请求异常 / success 不为 true
* ``skip`` — 动态端点（需 run_id）无历史运行记录
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import requests

SUCCESS_RE = re.compile(r'"success"\s*:\s*true')
RUN_ID_RE = re.compile(r'"run_id"\s*:\s*"([^"]+)"')

PROTOCOLS = ("tcp", "dns", "memcached", "ntp")


@dataclass
class CheckResult:
    group: str
    name: str
    path: str
    method: str = "GET"
    status: str = "pass"  # pass | warn | fail | skip
    message: str = ""
    http_code: Optional[int] = None
    duration_ms: int = 0


@dataclass
class SmokeReport:
    base_url: str
    groups: List[str] = field(default_factory=list)
    results: List[CheckResult] = field(default_factory=list)
    counts: Dict[str, int] = field(
        default_factory=lambda: {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
    )
    total_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "groups": self.groups,
            "results": [asdict(r) for r in self.results],
            "counts": dict(self.counts),
            "total_ms": self.total_ms,
        }


def _fetch(
    base_url: str, path: str, method: str = "GET", body: Optional[str] = None
) -> requests.Response:
    url = base_url.rstrip("/") + path
    return requests.request(
        method,
        url,
        headers={"Content-Type": "application/json"} if body else {},
        data=body,
        timeout=10,
    )


def _first_run_id(base_url: str, runs_path: str) -> Optional[str]:
    try:
        resp = _fetch(base_url, runs_path)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    m = RUN_ID_RE.search(resp.text)
    return m.group(1) if m else None


def _check(
    report: SmokeReport,
    group: str,
    name: str,
    path: str,
    nonempty_kw: str = "",
    method: str = "GET",
    body: Optional[str] = None,
    raw: bool = False,
) -> None:
    import time

    started = time.perf_counter()
    result = CheckResult(group=group, name=name, path=path, method=method)
    try:
        resp = _fetch(report.base_url, path, method, body)
        result.http_code = resp.status_code
        result.duration_ms = int((time.perf_counter() - started) * 1000)

        if resp.status_code != 200:
            result.status = "fail"
            result.message = f"HTTP {resp.status_code}"
        elif not raw and not SUCCESS_RE.search(resp.text):
            result.status = "fail"
            result.message = "响应缺少 success:true"
        elif nonempty_kw and nonempty_kw not in resp.text:
            result.status = "warn"
            result.message = "API 正常但数据为空（可能上游依赖故障或新部署空池）"
        else:
            result.status = "pass"
    except requests.RequestException as exc:
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.status = "fail"
        result.message = f"请求异常: {exc.__class__.__name__}"

    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1


def _check_dynamic(
    report: SmokeReport,
    group: str,
    name: str,
    path_tpl: str,
    runs_path: str,
    nonempty_kw: str = "",
) -> None:
    rid = _first_run_id(report.base_url, runs_path)
    if not rid:
        result = CheckResult(
            group=group,
            name=name,
            path=path_tpl % "<run_id>",
            status="skip",
            message="无历史运行记录",
        )
        report.results.append(result)
        report.counts["skip"] = report.counts.get("skip", 0) + 1
        return
    _check(
        report,
        group,
        f"{name} (run={rid})",
        path_tpl % rid,
        nonempty_kw=nonempty_kw,
    )


def run_smoke_test(base_url: str) -> SmokeReport:
    """执行全端点冒烟测试并返回报告。"""
    import time

    started = time.perf_counter()
    report = SmokeReport(base_url=base_url)

    # [1] 基础服务
    report.groups.append("基础服务")
    _check(report, "基础服务", "首页", "/", raw=True)
    _check(report, "基础服务", "系统信息", "/api/system/info")
    _check(report, "基础服务", "前端配置", "/api/config", raw=True)

    # [2] 服务器 IP 管理
    report.groups.append("服务器 IP 管理")
    for m in PROTOCOLS:
        _check(report, "服务器 IP 管理", f"servers/{m} 概览", f"/api/servers/{m}", raw=True)
        _check(report, "服务器 IP 管理", f"servers/{m} 文件列表", f"/api/servers/{m}/files", nonempty_kw='"full_path"')
        _check(report, "服务器 IP 管理", f"servers/{m} IP 明细", f"/api/servers/{m}/list")
        _check(report, "服务器 IP 管理", f"servers/{m} 地理分布", f"/api/servers/{m}/geo")
        _check(report, "服务器 IP 管理", f"servers/{m} 数量统计", "/api/servers/count", method="POST", body=json.dumps({"protocols": [m]}))

    # [3] 共享资源池 API
    report.groups.append("共享资源池 API")
    _check(report, "共享资源池 API", "共享池资源", "/api/attack-resource/resources")
    _check(report, "共享资源池 API", "资源来源列表", "/api/attack-resource/resources/sources")
    _check(report, "共享资源池 API", "可用国家列表", "/api/attack-resource/resources/countries")
    _check(report, "共享资源池 API", "抓取凭证列表", "/api/attack-resource/credentials")
    for p in PROTOCOLS:
        _check(report, "共享资源池 API", f"attack-resource/{p} 资源", f"/api/attack-resource/{p}/resources", nonempty_kw='"full_path"')
        _check(report, "共享资源池 API", f"attack-resource/{p} 运行", f"/api/attack-resource/{p}/runs")

    # [4] 协议扫描模块
    report.groups.append("协议扫描模块")
    _check(report, "协议扫描模块", "tcp-scan 资源列表", "/api/tcp-scan/resources")
    _check(report, "协议扫描模块", "tcp-scan 预检", "/api/tcp-scan/preflight")
    _check(report, "协议扫描模块", "tcp-scan 运行列表", "/api/tcp-scan/runs")
    _check(report, "协议扫描模块", "tcp-scan 状态", "/api/tcp-scan/state")
    for p in ("dns", "memcached", "ntp"):
        _check(report, "协议扫描模块", f"{p}-scan 资源列表", f"/api/{p}-scan/resources", nonempty_kw='"full_path"')
        _check(report, "协议扫描模块", f"{p}-scan 运行列表", f"/api/{p}-scan/runs")
        _check(report, "协议扫描模块", f"{p}-scan 状态", f"/api/{p}-scan/state")
    _check(report, "协议扫描模块", "dns 查询类型", "/api/dns-scan/query-types")
    _check(report, "协议扫描模块", "memcached 命令类型", "/api/memcached-scan/cmd-types")
    _check(report, "协议扫描模块", "ntp 探测动作", "/api/ntp-scan/probe-actions")

    # [5] 动态端点深测
    report.groups.append("动态端点深测")
    for p in PROTOCOLS:
        _check_dynamic(report, "动态端点深测", f"{p}-scan 运行详情", f"/api/{p}-scan/runs/%s", f"/api/{p}-scan/runs")
        _check_dynamic(report, "动态端点深测", f"{p}-scan 运行日志", f"/api/{p}-scan/runs/%s/logs", f"/api/{p}-scan/runs")
    for p in ("dns", "memcached", "ntp"):
        _check_dynamic(report, "动态端点深测", f"{p}-scan 扫描结果", f"/api/{p}-scan/runs/%s/results", f"/api/{p}-scan/runs")

    report.total_ms = int((time.perf_counter() - started) * 1000)
    return report
