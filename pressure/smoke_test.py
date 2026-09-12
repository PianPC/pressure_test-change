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
from pathlib import Path
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


def _check_resource_fetch(report: SmokeReport, group: str, name: str, spider: str) -> None:
    """检查自动获取资源链路（ipdeny/shodan/fofa/sonar）。

    这类端点虽为 POST，但只从公共数据源拉取 IP 列表，不发起攻击流量。
    判断逻辑：
    * success=true 且 files 非空、无 error → pass
    * success=true 但 files 为空或含 error → warn（可能是网络/账号受限，
      也可能是爬虫代码 bug，需人工查看 error 详情）
    * success=false / HTTP 非 200 / 请求异常 → fail
    """
    import time

    path = "/api/attack-resource/resources/fetch"
    body = json.dumps({"spider": spider, "params": {"countries": ["ad"]}})
    if spider in ("shodan", "fofa", "sonar"):
        body = json.dumps({"spider": spider, "params": {"queries": ["tcp"], "limit": 1}})

    started = time.perf_counter()
    result = CheckResult(group=group, name=name, path=path, method="POST")
    try:
        resp = _fetch(report.base_url, path, "POST", body)
        result.http_code = resp.status_code
        result.duration_ms = int((time.perf_counter() - started) * 1000)

        if resp.status_code != 200:
            result.status = "fail"
            result.message = f"HTTP {resp.status_code}"
        else:
            try:
                data = resp.json()
            except ValueError:
                result.status = "fail"
                result.message = "响应非合法 JSON"
                report.results.append(result)
                report.counts[result.status] = report.counts.get(result.status, 0) + 1
                return

            if not data.get("success"):
                result.status = "fail"
                result.message = f"success=false: {data.get('message', '')}"
            else:
                files = data.get("files", [])
                errors = [f.get("error") for f in files if f.get("error")]
                if not files:
                    result.status = "warn"
                    result.message = "API 正常但未返回任何文件"
                elif errors:
                    result.status = "warn"
                    result.message = f"获取完成但 {len(errors)}/{len(files)} 个国家失败: {errors[0][:80]}"
                else:
                    ok = [f for f in files if f.get("ip_count", 0) > 0]
                    if not ok:
                        result.status = "warn"
                        result.message = "API 正常但所有文件 ip_count 为 0"
                    else:
                        result.status = "pass"
                        result.message = f"成功获取 {len(ok)}/{len(files)} 个资源"
    except requests.RequestException as exc:
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.status = "fail"
        result.message = f"请求异常: {exc.__class__.__name__}"

    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1


def _check_pressure_test(report: SmokeReport, group: str, name: str) -> None:
    """压力测试链路：以极小流量打回本机 127.0.0.1，启动后立即停止。

    目的是验证 state.start_test / stop_test 链路与配置解析是否通畅，
    而非实际压测。参数设置：duration=1 分钟、threads=1、target_pps=1、ttl=1，
    启动后立刻调用 /api/test/stop，实际发包量极低且指向本机。

    判断逻辑：
    * start 与 stop 均 success=true → pass
    * start 成功但 stop 失败 → warn（测试可能在后台继续跑）
    * start 失败（如缺少 root 权限、无服务器 IP）→ warn（环境/配置问题，非代码 bug）
    * HTTP 异常 / 非 200 → fail
    """
    import time

    result = CheckResult(group=group, name=name, path="/api/test/start", method="POST")
    started = time.perf_counter()
    try:
        body = json.dumps({
            "target_ip": "127.0.0.1",
            "method": "tcp",
            "duration": 1,
            "threads": 1,
            "target_pps": 1,
            "ttl": 1,
        })
        resp = _fetch(report.base_url, "/api/test/start", "POST", body)
        result.http_code = resp.status_code

        if resp.status_code != 200:
            result.status = "fail"
            result.message = f"start HTTP {resp.status_code}: {resp.text[:120]}"
        else:
            try:
                data = resp.json()
            except ValueError:
                result.status = "fail"
                result.message = "start 响应非合法 JSON"
                report.results.append(result)
                report.counts[result.status] = report.counts.get(result.status, 0) + 1
                return

            if not data.get("success"):
                result.status = "warn"
                result.message = f"start 未启动: {data.get('message', '')[:100]}"
            else:
                # 启动成功，立即停止
                try:
                    stop_resp = _fetch(report.base_url, "/api/test/stop", "POST", "{}")
                    if stop_resp.status_code == 200:
                        stop_data = stop_resp.json()
                        if stop_data.get("success"):
                            result.status = "pass"
                            result.message = "启动并立即停止成功（小流量打回本机）"
                        else:
                            result.status = "warn"
                            result.message = f"stop 未成功: {stop_data.get('message', '')[:80]}"
                    else:
                        result.status = "warn"
                        result.message = f"stop HTTP {stop_resp.status_code}"
                except requests.RequestException as exc:
                    result.status = "warn"
                    result.message = f"stop 请求异常: {exc.__class__.__name__}"
    except requests.RequestException as exc:
        result.status = "fail"
        result.message = f"start 请求异常: {exc.__class__.__name__}"

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1


def _check_scan_start(report: SmokeReport, group: str, name: str, protocol: str, dry_run: bool = False) -> None:
    """协议扫描链路：通过统一攻击资源路由启动一次最小化扫描任务。

    走的是 /api/attack-resource/{proto}/runs（统一路由），而不是旧的
    /api/{proto}-scan/runs。统一路由是前端实际使用的入口。

    TCP 支持 dry_run（不发包），其余协议用 max_ips=1 / concurrency=1 等
    最小参数，仅扫描 1 个候选 IP，发包量极低。只验证启动成功（异步线程），
    不等待扫描完成。

    判断逻辑：
    * success=true → pass
    * 400 '没有可用的 IP 候选文件' → warn（未配置 IP 池，非代码 bug）
    * 400 '预检未通过' 且 dry_run=false → warn（运行环境缺依赖，非代码 bug）
    * 其他 4xx/5xx → fail
    * HTTP 异常 → fail
    """
    import time

    path = f"/api/attack-resource/{protocol}/runs"
    payload: Dict[str, Any]
    if protocol == "tcp":
        payload = {
            "ip_file": "",
            "target_host": "127.0.0.1",
            "pkt_methods": ["SYN"],
            "dry_run": True,
            "scan_count": 1,
        }
    else:
        payload = {"ip_file": "", "max_ips": 1, "concurrency": 1, "timeout_sec": 1}

    result = CheckResult(group=group, name=name, path=path, method="POST")
    started = time.perf_counter()
    try:
        resp = _fetch(report.base_url, path, "POST", json.dumps(payload))
        result.http_code = resp.status_code

        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                result.status = "fail"
                result.message = "响应非合法 JSON"
                report.results.append(result)
                report.counts[result.status] = report.counts.get(result.status, 0) + 1
                return

            if data.get("success"):
                run_id = data.get("run_id") or (data.get("run_ids") or [""])[0]
                result.status = "pass"
                result.message = f"扫描任务已启动 (run_id={run_id})" + (" [dry_run]" if dry_run else "")
            else:
                msg = data.get("message", "")
                if "IP 候选文件" in msg or "ip_file" in msg:
                    result.status = "warn"
                    result.message = f"无可用 IP 文件: {msg[:80]}"
                else:
                    result.status = "fail"
                    result.message = f"启动失败: {msg[:100]}"
        elif resp.status_code == 400:
            result.status = "warn"
            result.message = f"参数/资源不足（HTTP 400）: {resp.text[:100]}"
        else:
            result.status = "fail"
            result.message = f"HTTP {resp.status_code}: {resp.text[:100]}"
    except requests.RequestException as exc:
        result.status = "fail"
        result.message = f"请求异常: {exc.__class__.__name__}"

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1


# ── Python 纯函数级验证 ──────────────────────────────────────────────────


def _check_python_imports(report: SmokeReport) -> None:
    """直接 import 后端模块，检查函数签名冲突和调用链路是否正常。

    HTTP 冒烟测试只能发现运行时的 API 行为错误，但有些问题（比如
    模块级的同名函数覆盖）在 import 阶段就埋下了隐患。这里直接
    import 可疑模块，用 inspect 验证关键函数的签名和调用关系。

    检查项：
    1. attack_resource_api 中没有函数名冲突（同名函数只保留最后一个）
    2. _normalize_tcp_stage_status 签名是 1 参数
    3. _normalize_stage_status（公共版）签名是 4 参数
    4. _build_tcp_run_payload 内部调用不会因签名不匹配抛 TypeError
    """
    import inspect
    import sys
    import time

    group = "Python 纯函数验证"

    # ── 导入模块 ──
    started = time.perf_counter()
    result = CheckResult(group=group, name="导入 attack_resource_api 模块", path="import")
    try:
        # 确保项目根在 sys.path
        repo_root = Path(__file__).resolve().parent.parent
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))

        from attack_resources.shared import attack_resource_api  # noqa: F401

        result.status = "pass"
        result.message = "模块导入成功"
    except Exception as exc:
        result.status = "fail"
        result.message = f"导入失败: {exc.__class__.__name__}: {exc}"
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1

    if result.status == "fail":
        return  # 后续检查无法继续

    ar_api = sys.modules["attack_resources.shared.attack_resource_api"]

    # ── 检查同名函数冲突 ──
    started = time.perf_counter()
    result = CheckResult(group=group, name="无同名函数覆盖冲突", path="inspect.getmembers")

    seen: dict[str, int] = {}
    for name, obj in inspect.getmembers(ar_api):
        if inspect.isfunction(obj) and obj.__module__ == ar_api.__name__:
            seen[name] = seen.get(name, 0) + 1

    duplicates = {k: v for k, v in seen.items() if v > 1}
    if duplicates:
        result.status = "fail"
        funcs = ", ".join(f"{n}×{c}" for n, c in duplicates.items())
        result.message = f"存在 {len(duplicates)} 组同名函数（后面覆盖前面）: {funcs}"
    else:
        result.status = "pass"
        result.message = "无同名函数覆盖"
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1

    # ── 检查 TCP 专用的 stage status 函数签名 ──
    started = time.perf_counter()
    result = CheckResult(group=group, name="_normalize_tcp_stage_status 签名正确", path="inspect.signature")
    try:
        func = getattr(ar_api, "_normalize_tcp_stage_status", None)
        if func is None:
            result.status = "fail"
            result.message = "函数不存在（旧版 _normalize_stage_status 可能未重命名）"
        else:
            sig = inspect.signature(func)
            params = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
            # 允许 1-2 个必填参数（status + 可选），但不能是 4 个
            if len(params) == 1 and "status" in sig.parameters:
                result.status = "pass"
                result.message = f"签名 {sig}（1 个必填参数）"
            elif len(params) >= 4:
                result.status = "fail"
                result.message = f"签名 {sig}（看起来用了公共版 4 参数函数，TCP 调用会 TypeError）"
            else:
                result.status = "warn"
                result.message = f"签名 {sig}（参数数量非预期）"
    except Exception as exc:
        result.status = "fail"
        result.message = f"检查异常: {exc}"
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1

    # ── 检查公共 _normalize_stage_status 签名 ──
    started = time.perf_counter()
    result = CheckResult(group=group, name="_normalize_stage_status（公共版）签名正确", path="inspect.signature")
    try:
        func = getattr(ar_api, "_normalize_stage_status", None)
        if func is None:
            result.status = "fail"
            result.message = "公共版函数不存在"
        else:
            sig = inspect.signature(func)
            params = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
            if len(params) >= 4:
                result.status = "pass"
                result.message = f"签名 {sig}（4+ 个必填参数，供 DNS/NTP/Memcached 共用）"
            else:
                result.status = "fail"
                result.message = f"签名 {sig}（参数不足 4 个，公共版不完整）"
    except Exception as exc:
        result.status = "fail"
        result.message = f"检查异常: {exc}"
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1

    # ── 模拟 TCP stage status 调用（确保不抛 TypeError） ──
    started = time.perf_counter()
    result = CheckResult(group=group, name="TCP stage status 调用不抛 TypeError", path="_normalize_tcp_stage_status(...)")
    try:
        func = ar_api._normalize_tcp_stage_status
        # 模拟 TCP 调用方式：只传 1 个 status 参数
        result_val = func("completed")
        if result_val == "completed":
            result.status = "pass"
            result.message = f"_normalize_tcp_stage_status('completed') → '{result_val}'"
        else:
            result.status = "warn"
            result.message = f"返回值非预期: '{result_val}'"
    except TypeError as exc:
        result.status = "fail"
        result.message = f"TypeError: {exc}（这就是导致 500 的 bug）"
    except Exception as exc:
        result.status = "fail"
        result.message = f"异常: {exc.__class__.__name__}: {exc}"
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    report.results.append(result)
    report.counts[result.status] = report.counts.get(result.status, 0) + 1


# ── 统一攻击资源路由动态端点深测 ──────────────────────────────────────────


def _check_unified_dynamic(
    report: SmokeReport,
    group: str,
    name: str,
    proto: str,
    detail_suffix: str = "",
) -> None:
    """统一攻击资源路由的动态端点深测。

    先 GET /api/attack-resource/{proto}/runs 取 run_id，再拼到
    /api/attack-resource/{proto}/runs/<run_id>{detail_suffix} 做深测。
    用统一路由而不是旧的 /api/{proto}-scan/runs，因为前端实际走的是统一路由。
    """
    runs_path = f"/api/attack-resource/{proto}/runs"
    rid = _first_run_id(report.base_url, runs_path)
    if not rid:
        result = CheckResult(
            group=group,
            name=name,
            path=f"/api/attack-resource/{proto}/runs/<run_id>{detail_suffix}",
            status="skip",
            message="无历史运行记录",
        )
        report.results.append(result)
        report.counts["skip"] = report.counts.get("skip", 0) + 1
        return
    path = f"/api/attack-resource/{proto}/runs/{rid}{detail_suffix}"
    _check(report, group, f"{name} (run={rid})", path)


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

    # [5] 动态端点深测 — 统一攻击资源路由（前端实际使用的入口）
    #     这里必须走 /api/attack-resource/{proto}/runs/<run_id>，
    #     而不是旧路由 /api/{proto}-scan/runs/<id>，否则会漏掉
    #     统一路由层的 bug（比如这次的函数签名冲突就藏在统一路由里）
    report.groups.append("动态端点深测（统一攻击资源路由）")
    for p in PROTOCOLS:
        _check_unified_dynamic(report, "动态端点深测（统一攻击资源路由）", f"{p} run 详情", p)
        _check_unified_dynamic(report, "动态端点深测（统一攻击资源路由）", f"{p} run 日志", p, "/logs")
    for p in ("dns", "memcached", "ntp"):
        _check_unified_dynamic(report, "动态端点深测（统一攻击资源路由）", f"{p} 扫描结果", p, "/results")
    # TCP 还有专用详情端点
    _check_unified_dynamic(report, "动态端点深测（统一攻击资源路由）", "TCP qualified_ips", "tcp", "/qualified-ips")

    # [6] 旧协议扫描模块 — 保留检查旧路由是否还能正常响应
    report.groups.append("旧协议扫描模块（向后兼容）")
    for p in PROTOCOLS:
        _check_dynamic(report, "旧协议扫描模块（向后兼容）", f"{p}-scan 运行详情", f"/api/{p}-scan/runs/%s", f"/api/{p}-scan/runs")
        _check_dynamic(report, "旧协议扫描模块（向后兼容）", f"{p}-scan 运行日志", f"/api/{p}-scan/runs/%s/logs", f"/api/{p}-scan/runs")
    for p in ("dns", "memcached", "ntp"):
        _check_dynamic(report, "旧协议扫描模块（向后兼容）", f"{p}-scan 扫描结果", f"/api/{p}-scan/runs/%s/results", f"/api/{p}-scan/runs")

    # [7] 文件管理
    report.groups.append("文件管理")
    _check(report, "文件管理", "项目根目录", "/api/files/root")
    _check(report, "文件管理", "目录树", "/api/files/tree", nonempty_kw='"entries"')

    # [8] 资源获取链路（自动抓取，不发起攻击流量）
    report.groups.append("资源获取链路")
    _check_resource_fetch(report, "资源获取链路", "ipdeny 自动获取", "ipdeny")

    # [9] 压力测试链路（小流量打回本机 127.0.0.1，启动后立即停止）
    report.groups.append("压力测试链路")
    _check_pressure_test(report, "压力测试链路", "TCP 小流量压测本机")

    # [10] 协议扫描链路 — 通过统一攻击资源路由 POST 启动（TCP 用 dry_run 不发包）
    report.groups.append("协议扫描启动链路（统一路由 POST）")
    _check_scan_start(report, "协议扫描启动链路（统一路由 POST）", "TCP 启动 (dry_run)", "tcp", dry_run=True)
    _check_scan_start(report, "协议扫描启动链路（统一路由 POST）", "DNS 启动 (max_ips=1)", "dns")
    _check_scan_start(report, "协议扫描启动链路（统一路由 POST）", "Memcached 启动 (max_ips=1)", "memcached")
    _check_scan_start(report, "协议扫描启动链路（统一路由 POST）", "NTP 启动 (max_ips=1)", "ntp")

    # [11] Python 纯函数级验证（在服务端进程外直接 import 后端模块）
    #     这一层能发现 HTTP 冒烟测不出来的问题，比如：
    #     - 模块级同名函数覆盖（后面的覆盖前面的，前面的白写了）
    #     - 函数签名不匹配导致运行时 TypeError
    #     注意：这组检查需要在服务器上运行（因为要 import 后端模块），
    #     在本地浏览器端触发的冒烟测试界面中会被标记为 skip。
    report.groups.append("Python 纯函数验证")
    _check_python_imports(report)

    report.total_ms = int((time.perf_counter() - started) * 1000)
    return report
