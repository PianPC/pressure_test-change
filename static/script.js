let pollingInterval = null;
let selectedProtocols = [];
let isMultiProtocol = false;
let ppsChart = null;
let ppsDataPoints = [];
let latencyChart = null;
let latencyDataPoints = [];
let latencyMonitorInterval = null;
let isMonitoringLatency = false;
let isLatencySamplePending = false;
let baselineLatency = null;
let baselineSamples = [];
let attackStartTimeForLatency = null;
let currentProto = "memcached";
let serverGlobe = null;
let lastGeoPoints = [];
let lastGeoAreas = [];
let serverMapMode = "3d";
let serverMapShapes = null;
let serverMap2dZoomTransform = null;
let isGeoMapLoading = false;
let tcpScanPollInterval = null;
let currentTcpRunId = null;
let currentTcpRuns = [];
let currentTcpFile = null;

const MAX_PPS_POINTS = 40;
const MAX_LATENCY_POINTS = 60;
const CHINA_REGION_ADCODE = {
    BJ: "110000",
    TJ: "120000",
    HE: "130000",
    SX: "140000",
    NM: "150000",
    LN: "210000",
    JL: "220000",
    HL: "230000",
    SH: "310000",
    JS: "320000",
    ZJ: "330000",
    AH: "340000",
    FJ: "350000",
    JX: "360000",
    SD: "370000",
    HA: "410000",
    HB: "420000",
    HN: "430000",
    GD: "440000",
    GX: "450000",
    HI: "460000",
    CQ: "500000",
    SC: "510000",
    GZ: "520000",
    YN: "530000",
    XZ: "540000",
    SN: "610000",
    GS: "620000",
    QH: "630000",
    NX: "640000",
    XJ: "650000",
    TW: "710000",
    HK: "810000",
    MO: "820000"
};

const latencyTimeoutBandPlugin = {
    id: "latencyTimeoutBand",
    getBand(chart, index) {
        const dataset = chart.data.datasets?.[0];
        const xScale = chart.scales.x;
        if (!dataset || !xScale) return null;
        const x = xScale.getPixelForValue(index);
        const prevX = index > 0 ? xScale.getPixelForValue(index - 1) : x;
        const nextX = index < dataset.data.length - 1 ? xScale.getPixelForValue(index + 1) : x;
        const spacing = Math.max(Math.abs(nextX - x), Math.abs(x - prevX), 14);
        const bandWidth = Math.max(12, Math.min(34, spacing * 0.72));
        return { x, left: x - bandWidth / 2, right: x + bandWidth / 2, width: bandWidth };
    },
    beforeDatasetsDraw(chart) {
        const dataset = chart.data.datasets?.[0];
        if (!dataset?.data?.length) return;
        const { ctx, chartArea, scales } = chart;
        const xScale = scales.x;
        if (!ctx || !chartArea || !xScale) return;

        dataset.data.forEach((value, index) => {
            if (value !== null) return;
            const band = this.getBand(chart, index);
            if (!band) return;

            ctx.save();
            ctx.fillStyle = "rgba(255, 79, 109, 0.18)";
            ctx.fillRect(band.left, chartArea.top, band.width, chartArea.bottom - chartArea.top);
            ctx.strokeStyle = "rgba(255, 79, 109, 0.78)";
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.moveTo(band.x, chartArea.top);
            ctx.lineTo(band.x, chartArea.bottom);
            ctx.stroke();
            ctx.restore();
        });
    },
    afterDatasetsDraw(chart) {
        const dataset = chart.data.datasets?.[0];
        if (!dataset?.data?.length) return;
        const { ctx, scales } = chart;
        const xScale = scales.x;
        const yScale = scales.y;
        if (!ctx || !xScale || !yScale) return;

        dataset.data.forEach((value, index) => {
            if (value !== null) return;
            const band = this.getBand(chart, index);
            if (!band) return;

            const prevIndex = findPreviousNumericIndex(dataset.data, index);
            const nextIndex = findNextNumericIndex(dataset.data, index);

            ctx.save();
            ctx.strokeStyle = dataset.borderColor || "#ffbd5c";
            ctx.lineWidth = dataset.borderWidth || 2;
            ctx.lineCap = "round";
            ctx.lineJoin = "round";

            if (prevIndex !== -1 && prevIndex === index - 1) {
                const startX = xScale.getPixelForValue(prevIndex);
                const y = yScale.getPixelForValue(dataset.data[prevIndex]);
                drawSmoothTimeoutConnector(ctx, startX, y, band.left, y);
            }

            if (nextIndex !== -1 && nextIndex === index + 1) {
                const endX = xScale.getPixelForValue(nextIndex);
                const y = yScale.getPixelForValue(dataset.data[nextIndex]);
                drawSmoothTimeoutConnector(ctx, band.right, y, endX, y);
            }

            ctx.restore();
        });
    }
};

function findPreviousNumericIndex(data, startIndex) {
    for (let index = startIndex - 1; index >= 0; index -= 1) {
        if (typeof data[index] === "number") return index;
        if (data[index] === null) break;
    }
    return -1;
}

function findNextNumericIndex(data, startIndex) {
    for (let index = startIndex + 1; index < data.length; index += 1) {
        if (typeof data[index] === "number") return index;
        if (data[index] === null) break;
    }
    return -1;
}

function drawSmoothTimeoutConnector(ctx, fromX, fromY, toX, toY) {
    const controlOffset = Math.max(8, Math.abs(toX - fromX) * 0.45);
    ctx.beginPath();
    ctx.moveTo(fromX, fromY);
    ctx.bezierCurveTo(fromX + controlOffset, fromY, toX - controlOffset, toY, toX, toY);
    ctx.stroke();
}

document.addEventListener("DOMContentLoaded", () => {
    localizeTcpScanView();
    initParticles();
    initChart();
    initLatencyChart();
    initServerGlobe();
    setupNavigation();
    initProtocolCheckboxes();
    bindControls();
    toggleMultiProtocol();
    loadAllServerCounts();
    loadServerListForEdit();
    loadServerGeoMap();
    initTcpScan();
    pollStatus();
    updateSystemInfo();
    updateDetailedSystemInfo();
    setInterval(updateSystemInfo, 3000);
    setInterval(updateDetailedSystemInfo, 2000);
});

function localizeTcpScanView() {
    const log = document.getElementById("tcpPipelineLog");
    if (log && log.textContent.trim() === "No TCP scan selected.") {
        log.textContent = "尚未选择 TCP 扫描。";
    }
}

function bindControls() {
    document.getElementById("multi_protocol")?.addEventListener("change", toggleMultiProtocol);
    document.getElementById("startBtn")?.addEventListener("click", startTest);
    document.getElementById("stopBtn")?.addEventListener("click", stopTest);
    document.getElementById("resetBtn")?.addEventListener("click", resetTest);
    document.getElementById("method")?.addEventListener("change", updateMethodSettings);
    document.getElementById("startLatencyMonitor")?.addEventListener("click", startLatencyMonitoring);
    document.getElementById("stopLatencyMonitor")?.addEventListener("click", stopLatencyMonitoring);
    document.getElementById("saveServerListBtn")?.addEventListener("click", saveServerList);
    document.getElementById("refreshServerListBtn")?.addEventListener("click", refreshServerResources);
    document.getElementById("refreshGeoMapBtn")?.addEventListener("click", loadServerGeoMap);
    document.querySelectorAll(".map-view-btn").forEach((btn) => {
        btn.addEventListener("click", () => switchServerMapMode(btn.dataset.mapView || "3d"));
    });
    document.getElementById("tcpStartBtn")?.addEventListener("click", startTcpScan);
    document.getElementById("tcpStopBtn")?.addEventListener("click", stopTcpScan);
    document.getElementById("tcpRefreshBtn")?.addEventListener("click", refreshTcpScan);
    document.getElementById("tcpClearRunsBtn")?.addEventListener("click", clearTcpRunRecords);

    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach((item) => item.classList.remove("active"));
            btn.classList.add("active");
            currentProto = btn.dataset.proto || "memcached";
            loadServerListForEdit();
            loadServerGeoMap();
        });
    });
}

function setupNavigation() {
    document.querySelectorAll(".nav-item").forEach((item) => {
        item.addEventListener("click", (event) => {
            event.preventDefault();
            const view = item.dataset.view;
            if (!view) return;
            document.querySelectorAll(".nav-item").forEach((nav) => nav.classList.remove("active"));
            document.querySelectorAll(".view-pane").forEach((pane) => pane.classList.remove("active"));
            item.classList.add("active");
            document.getElementById(`view-${view}`)?.classList.add("active");
            if (view === "servers") {
                loadServerListForEdit();
                loadServerGeoMap();
                resizeServerGlobe();
            }
            if (view === "tcp-scan") {
                refreshTcpScan();
            }
            resizeCharts();
        });
    });
}

async function initTcpScan() {
    bindTcpModalControls();
    await loadTcpResources();
    await refreshTcpScan();
}

function bindTcpModalControls() {
    document.getElementById("tcpStopCleanupBtn")?.addEventListener("click", () => stopTcpScan(true));
    document.getElementById("tcpFileModalClose")?.addEventListener("click", closeTcpFileModal);
    document.querySelector('[data-dismiss="tcp-file-modal"]')?.addEventListener("click", closeTcpFileModal);
    document.getElementById("tcpFileSaveBtn")?.addEventListener("click", saveTcpFileContent);
    document.getElementById("tcpFileReloadBtn")?.addEventListener("click", reloadTcpFileContent);
}

async function loadTcpResources() {
    const select = document.getElementById("tcpIpFile");
    if (!select) return;
    try {
        const response = await fetch("/api/tcp-scan/resources");
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "TCP 资源加载失败");
        select.innerHTML = "";
        (data.resources || []).forEach((resource) => {
            const option = document.createElement("option");
            option.value = resource.path || resource.filename;
            option.textContent = `${resource.filename} (${resource.non_empty_lines || 0})`;
            if (resource.filename === "test.txt") option.selected = true;
            select.appendChild(option);
        });
    } catch (error) {
        showNotification(`TCP 资源加载失败：${error.message}`, "error");
    }
}

function readTcpScanPayload() {
    const checkedMethods = Array.from(document.querySelectorAll('#tcpMethodChecks input[type="checkbox"]:checked'))
        .map((input) => input.value);
    return {
        ip_file: document.getElementById("tcpIpFile")?.value || "",
        target_host: document.getElementById("tcpTargetHost")?.value.trim() || "",
        pkt_method: document.getElementById("tcpPktMethod")?.value || "PSH",
        pkt_methods: checkedMethods.length ? checkedMethods : undefined,
        scan_rate: readNumber("tcpScanRate", 2500),
        ttl: readNumber("tcpTtl", 255),
        scan_count: readNumber("tcpScanCount", 10),
        result_limit: readNumberAllowZero("tcpResultLimit", 30),
        length_threshold: readNumberAllowZero("tcpLengthThreshold", 2000),
        network_interface: document.getElementById("tcpNetworkInterface")?.value.trim() || "eth0",
        dry_run: Boolean(document.getElementById("tcpDryRun")?.checked)
    };
}

async function startTcpScan() {
    const payload = readTcpScanPayload();
    if (!payload.ip_file || !payload.target_host) {
        showNotification("TCP 扫描需要选择 IP 资源并填写目标主机", "error");
        return;
    }
    const methods = payload.pkt_methods?.length ? payload.pkt_methods : [payload.pkt_method];
    if (!methods.length) {
        showNotification("请至少选择一种报文方法", "error");
        return;
    }
    setTcpControls(true, false);
    try {
        if (!payload.dry_run) {
            for (const method of methods) {
                const report = await runTcpPreflight({ ...payload, pkt_method: method });
                if (!report.ok) {
                    setTcpControls(false, false);
                    return;
                }
            }
        } else {
            setText("tcpPreflightStatus", "当前为模拟运行，将跳过真实扫描预检。");
        }
        const result = await postJson("/api/tcp-scan/runs", payload);
        if (!result.success) throw new Error(result.message || "TCP 扫描启动失败");
        showNotification(`已创建 ${result.run_ids?.length || methods.length} 个 TCP 扫描任务`, "success");
        if (Array.isArray(result.run_ids) && result.run_ids.length) {
            currentTcpRunId = result.run_ids[0];
        }
        startTcpPolling();
        await refreshTcpScan();
    } catch (error) {
        showNotification(`TCP 扫描启动失败：${getTcpApiMessage(error.message, error.message)}`, "error");
        setTcpControls(false, false);
    }
}

async function runTcpPreflight(payload) {
    const params = new URLSearchParams({
        dry_run: String(Boolean(payload.dry_run)),
        pkt_method: payload.pkt_method || "PSH",
        network_interface: payload.network_interface || "eth0"
    });
    const response = await fetch(`/api/tcp-scan/preflight?${params.toString()}`);
    const data = await response.json();
    if (!response.ok || (!data?.success && !data?.report)) {
        const message = data?.message || data?.error || `HTTP ${response.status}`;
        setText("tcpPreflightStatus", `预检请求失败：${message}`);
        showNotification(`预检请求失败：${message}`, "error");
        return { ok: false, checks: [] };
    }
    const checks = data.report?.checks || [];
    const failures = checks
        .filter((item) => !item.ok)
        .map((item) => `${item.label}：${item.message}${item.path ? `：${item.path}` : ""}`);
    const statusText = failures.length
        ? `预检未通过：${failures.join("；")}`
        : "预检通过，可以执行真实扫描。";
    setText("tcpPreflightStatus", statusText);
    if (failures.length) {
        showNotification(statusText, "error");
        return { ok: false, checks };
    }
    return { ok: true, checks };
}

async function stopTcpScan(cleanup = false) {
    if (!currentTcpRunId) {
        showNotification("尚未选择 TCP 扫描任务", "error");
        return;
    }
    try {
        const result = await postJson(`/api/tcp-scan/runs/${currentTcpRunId}/stop`, { cleanup });
        showNotification(
            getTcpApiMessage(result.message, cleanup ? "已请求停止并清理任务" : "已请求停止 TCP 扫描"),
            result.success ? "info" : "error"
        );
        await refreshTcpScan();
    } catch (error) {
        showNotification(`TCP 扫描停止失败：${getTcpApiMessage(error.message, error.message)}`, "error");
    }
}

async function clearTcpRunRecords() {
    if (!confirm("清除所有已结束 TCP 扫描记录及产物？运行中的任务会保留。")) {
        return;
    }
    const clearBtn = document.getElementById("tcpClearRunsBtn");
    if (clearBtn) clearBtn.disabled = true;
    try {
        const response = await fetch("/api/tcp-scan/runs", { method: "DELETE" });
        const data = await readJsonResponse(response);
        if (!response.ok || !data?.success) {
            throw new Error(data?.message || data?.error || `HTTP ${response.status}`);
        }
        if ((data.deleted || []).includes(currentTcpRunId)) {
            currentTcpRunId = null;
        }
        const skippedText = data.skipped?.length ? `，保留 ${data.skipped.length} 个运行中任务` : "";
        showNotification(`${data.message || "记录已清除"}${skippedText}`, "success");
        await refreshTcpScan();
    } catch (error) {
        showNotification(`清除记录失败：${getTcpApiMessage(error.message, error.message)}`, "error");
    } finally {
        if (clearBtn) clearBtn.disabled = false;
    }
}

function startTcpPolling() {
    if (tcpScanPollInterval) clearInterval(tcpScanPollInterval);
    tcpScanPollInterval = setInterval(refreshTcpScan, 1000);
}

async function refreshTcpScan() {
    try {
        const response = await fetch("/api/tcp-scan/runs");
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "TCP 扫描记录加载失败");
        currentTcpRuns = data.runs || [];
        renderTcpRunList(currentTcpRuns, data.active_run_ids || []);
        const activeRunIds = data.active_run_ids || [];
        const selected = currentTcpRunId
            ? currentTcpRuns.find((run) => run.run_id === currentTcpRunId)
            : null;
        const preferred = selected
            || (activeRunIds.length ? currentTcpRuns.find((run) => run.run_id === activeRunIds[0]) : null)
            || currentTcpRuns[0];
        if (!preferred) {
            renderTcpEmptyState();
            return;
        }
        currentTcpRunId = preferred.run_id;
        await loadTcpRunDetail(preferred.run_id);
        if (!activeRunIds.length && tcpScanPollInterval) {
            clearInterval(tcpScanPollInterval);
            tcpScanPollInterval = null;
        }
    } catch (error) {
        console.warn("TCP 扫描刷新失败", error);
    }
}

function renderTcpRunList(runs, activeRunIds) {
    const container = document.getElementById("tcpRunList");
    if (!container) return;
    if (!runs.length) {
        container.innerHTML = `<div class="info-text">暂无 TCP 扫描任务。</div>`;
        return;
    }
    container.innerHTML = runs.map((run) => {
        const isActive = run.run_id === currentTcpRunId;
        const running = activeRunIds.includes(run.run_id);
        const metaText = running ? "执行中" : getTcpStatusText(run.status);
        return `
            <button type="button" class="tcp-run-item ${isActive ? "active" : ""}" data-run-id="${escapeHtml(run.run_id)}">
                <span class="tcp-run-item-main">
                    <span>${escapeHtml(run.run_id)}</span>
                    <span>${escapeHtml(run.target_host || "-")}</span>
                </span>
                <span class="tcp-run-item-meta">
                    <span>${escapeHtml(run.pkt_method || "-")}</span>
                    <strong>${escapeHtml(metaText)}</strong>
                </span>
            </button>
        `;
    }).join("");
    container.querySelectorAll("[data-run-id]").forEach((item) => {
        item.addEventListener("click", async () => {
            currentTcpRunId = item.getAttribute("data-run-id");
            renderTcpRunList(currentTcpRuns, activeRunIds);
            await loadTcpRunDetail(currentTcpRunId);
        });
    });
}

async function loadTcpRunDetail(runId) {
    const response = await fetch(`/api/tcp-scan/runs/${runId}`);
    const data = await response.json();
    if (!data.success) throw new Error(data.message || "TCP 扫描详情加载失败");
    const summary = data.summary || {};
    renderTcpSummary(summary);
    await loadTcpRunLog(runId);
}

async function loadTcpRunLog(runId) {
    const response = await fetch(`/api/tcp-scan/runs/${runId}/logs?tail=160`);
    const data = await response.json();
    if (data.success) {
        const box = document.getElementById("tcpPipelineLog");
        if (box) box.textContent = data.log || "";
    }
}

function renderTcpSummary(summary) {
    const status = summary.status || "unknown";
    const config = summary.config || {};
    setText("tcpStatus", getTcpStatusText(status));
    setText("tcpRunId", summary.run_id || "-");
    setText("tcpRunMethod", config.pkt_method || "-");
    setText("tcpRunHost", config.target_host || "-");
    renderTcpMeta(summary);
    renderTcpArtifacts(summary.files || []);
    renderTcpStages(summary.stages || {}, summary.current_stage || null);
    renderTcpRuntimeError(summary);
    setTcpControls(summary.is_running || status === "running" || status === "stopping", Boolean(summary.is_running));
}

function renderTcpMeta(summary) {
    const container = document.getElementById("tcpRunMeta");
    if (!container) return;
    const items = [
        ["当前阶段", getTcpStageText(summary.current_stage || "-")],
        ["开始时间", summary.started_at || "-"],
        ["结束时间", summary.ended_at || "-"],
        ["模拟运行", summary.config?.dry_run ? "是" : "否"],
        ["停止请求", summary.stop_requested ? "已请求" : "未请求"],
        ["失败原因", summary.error || summary.runtime_error || "-"]
    ];
    container.innerHTML = items.map(([label, value]) => `
        <div class="tcp-run-meta-item">
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(value)}</strong>
        </div>
    `).join("");
}

function renderTcpArtifacts(files) {
    const container = document.getElementById("tcpArtifacts");
    if (!container) return;
    if (!files.length) {
        container.innerHTML = `<div class="info-text">暂无输出文件。</div>`;
        return;
    }
    container.innerHTML = files.map((file) => `
        <button type="button" class="tcp-artifact-item tcp-file-button" data-file-name="${escapeHtml(file.name)}">
            <span>${escapeHtml(file.name)}</span>
            <strong>${formatBytes(file.bytes || 0)}</strong>
        </button>
    `).join("");
    container.querySelectorAll("[data-file-name]").forEach((item) => {
        item.addEventListener("click", () => openTcpFileModal(item.getAttribute("data-file-name")));
    });
}

function renderTcpStages(stages, currentStage) {
    const container = document.getElementById("tcpStages");
    if (!container) return;
    const order = ["prepare_zmap", "run_zmap_scan", "process_scan_csv", "extract_ips", "run_amplification_test", "analyze_amplification_log"];
    container.innerHTML = order.map((stage) => {
        const state = stages[stage]?.status || (stage === currentStage ? "running" : "pending");
        return `<div class="tcp-stage-item"><span>${getTcpStageText(stage)}</span><strong>${escapeHtml(getTcpStatusText(state))}</strong></div>`;
    }).join("");
}

function renderTcpRuntimeError(summary) {
    const errorBox = document.getElementById("tcpRuntimeError");
    if (!errorBox) return;
    const error = summary.error || summary.runtime_error || "";
    errorBox.textContent = error ? `失败原因：${error}` : "";
}

function renderTcpEmptyState() {
    currentTcpRunId = null;
    setText("tcpStatus", "空闲");
    setText("tcpRunId", "-");
    setText("tcpRunMethod", "-");
    setText("tcpRunHost", "-");
    setText("tcpPreflightStatus", "真实扫描前会自动执行环境预检。");
    const runList = document.getElementById("tcpRunList");
    if (runList) runList.innerHTML = `<div class="info-text">暂无 TCP 扫描任务。</div>`;
    const stages = document.getElementById("tcpStages");
    if (stages) stages.innerHTML = "";
    const artifacts = document.getElementById("tcpArtifacts");
    if (artifacts) artifacts.innerHTML = `<div class="info-text">暂无 TCP 扫描记录。</div>`;
    const log = document.getElementById("tcpPipelineLog");
    if (log) log.textContent = "尚未选择 TCP 扫描。";
    const meta = document.getElementById("tcpRunMeta");
    if (meta) meta.innerHTML = "";
    const errorBox = document.getElementById("tcpRuntimeError");
    if (errorBox) errorBox.textContent = "";
    setTcpControls(false, false);
}

function setTcpControls(hasRunningTask, canStopCurrent) {
    const stop = document.getElementById("tcpStopBtn");
    const stopCleanup = document.getElementById("tcpStopCleanupBtn");
    if (stop) stop.disabled = !canStopCurrent;
    if (stopCleanup) stopCleanup.disabled = !canStopCurrent;
}

async function openTcpFileModal(filename) {
    if (!currentTcpRunId || !filename) return;
    try {
        const response = await fetch(`/api/tcp-scan/runs/${currentTcpRunId}/files/${encodeURIComponent(filename)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "文件加载失败");
        currentTcpFile = data.file;
        renderTcpFileModal(data.file);
        const modal = document.getElementById("tcpFileModal");
        if (modal) modal.hidden = false;
    } catch (error) {
        showNotification(`文件加载失败：${error.message}`, "error");
    }
}

function renderTcpFileModal(file) {
    const title = document.getElementById("tcpFileModalTitle");
    const body = document.getElementById("tcpFileModalBody");
    const saveBtn = document.getElementById("tcpFileSaveBtn");
    const reloadBtn = document.getElementById("tcpFileReloadBtn");
    if (title) title.textContent = file.name || "文件内容";
    if (reloadBtn) reloadBtn.disabled = false;
    if (file.type === "db") {
        if (saveBtn) saveBtn.disabled = true;
        if (body) body.innerHTML = renderTcpDbPreview(file.preview);
        return;
    }
    if (saveBtn) saveBtn.disabled = !file.editable;
    if (body) {
        body.innerHTML = file.editable
            ? `<textarea id="tcpFileEditor">${escapeHtml(file.content || "")}</textarea>`
            : `<pre>${escapeHtml(file.content || "")}</pre>`;
        if (file.editable) {
            const textarea = document.getElementById("tcpFileEditor");
            if (textarea) textarea.value = file.content || "";
        }
    }
}

function renderTcpDbPreview(preview) {
    const tables = preview?.preview_tables || [];
    if (!tables.length) {
        return `<div class="tcp-db-preview">该数据库暂无可预览数据。</div>`;
    }
    return `
        <div class="tcp-db-preview">
            <div>共 ${preview.tables?.length || 0} 张表：${escapeHtml((preview.tables || []).join(", "))}</div>
            ${tables.map((table) => `
                <div class="tcp-db-table">
                    <table>
                        <thead>
                            <tr>${table.columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr>
                        </thead>
                        <tbody>
                            ${table.rows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(String(value ?? ""))}</td>`).join("")}</tr>`).join("")}
                        </tbody>
                    </table>
                </div>
            `).join("")}
        </div>
    `;
}

function closeTcpFileModal() {
    const modal = document.getElementById("tcpFileModal");
    if (modal) modal.hidden = true;
    currentTcpFile = null;
}

async function saveTcpFileContent() {
    if (!currentTcpRunId || !currentTcpFile?.editable) return;
    const textarea = document.getElementById("tcpFileEditor");
    const content = textarea?.value ?? "";
    try {
        const result = await fetch(`/api/tcp-scan/runs/${currentTcpRunId}/files/${encodeURIComponent(currentTcpFile.name)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });
        const data = await result.json();
        if (!data.success) throw new Error(data.message || "文件保存失败");
        showNotification(data.message || "文件已保存", "success");
        await refreshTcpScan();
        await reloadTcpFileContent();
    } catch (error) {
        showNotification(`文件保存失败：${error.message}`, "error");
    }
}

async function reloadTcpFileContent() {
    if (!currentTcpFile?.name) return;
    await openTcpFileModal(currentTcpFile.name);
}

function readNumberAllowZero(id, fallback) {
    const value = Number(document.getElementById(id)?.value);
    return Number.isFinite(value) && value >= 0 ? value : fallback;
}

function getTcpStageText(stage) {
    return {
        prepare_zmap: "准备 ZMap",
        run_zmap_scan: "执行 ZMap 扫描",
        process_scan_csv: "处理扫描 CSV",
        extract_ips: "提取 IP",
        run_amplification_test: "执行放大测试",
        analyze_amplification_log: "分析放大日志",
        "-": "-"
    }[stage] || stage || "-";
}

function getTcpStatusText(status) {
    return {
        idle: "空闲",
        running: "运行中",
        stopping: "停止中",
        stopped: "已停止",
        completed: "已完成",
        failed: "失败",
        skipped: "已跳过",
        pending: "等待中",
        unknown: "未知"
    }[status] || status || "未知";
}

function getTcpApiMessage(message, fallback) {
    if (!message) return fallback;
    return {
        "TCP scan started": "TCP 扫描已启动",
        "TCP scan is already running": "TCP 扫描正在运行",
        "Stopping TCP scan": "正在停止 TCP 扫描",
        "No running process found": "未找到正在运行的扫描进程",
        "Run not found": "未找到扫描记录"
    }[message] || message;
}

function formatBytes(bytes) {
    const units = ["B", "KB", "MB", "GB"];
    let value = Number(bytes) || 0;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
        value /= 1024;
        index += 1;
    }
    return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function initChart() {
    const ctx = document.getElementById("ppsChart")?.getContext("2d");
    if (!ctx || !window.Chart) return;
    ppsChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "发送速率 (pps)",
                data: [],
                borderColor: "#40e7ff",
                backgroundColor: "rgba(64, 231, 255, 0.12)",
                borderWidth: 2,
                tension: 0.28,
                pointRadius: 2,
                pointBackgroundColor: "#ff4f6d",
                fill: true
            }]
        },
        options: baseChartOptions("PPS")
    });
}

function initLatencyChart() {
    const ctx = document.getElementById("latencyChart")?.getContext("2d");
    if (!ctx || !window.Chart) return;
    latencyChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "TCP 延迟 (ms)",
                data: [],
                borderColor: "#ffbd5c",
                backgroundColor: "rgba(255, 189, 92, 0.12)",
                borderWidth: 2,
                tension: 0.25,
                pointRadius: 2,
                fill: true,
                spanGaps: false
            }]
        },
        plugins: [latencyTimeoutBandPlugin],
        options: {
            ...baseChartOptions("延迟 (ms)"),
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(143, 168, 199, 0.13)" },
                    ticks: { color: "#8fa8c7" },
                    title: { display: true, text: "延迟 (ms)", color: "#8fa8c7" }
                },
                x: {
                    grid: { color: "rgba(143, 168, 199, 0.09)" },
                    ticks: { color: "#8fa8c7" },
                    title: { display: true, text: "时间 (秒)", color: "#8fa8c7" }
                }
            },
            plugins: {
                legend: { labels: { color: "#c7d8ef" } },
                tooltip: {
                    callbacks: {
                        label: (ctx) => ctx.raw === null ? "超时" : `${ctx.raw} ms`
                    }
                }
            }
        }
    });
}

function baseChartOptions(yTitle) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
            legend: { labels: { color: "#c7d8ef" } }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: { color: "rgba(143, 168, 199, 0.13)" },
                ticks: { color: "#8fa8c7" },
                title: { display: true, text: yTitle, color: "#8fa8c7" }
            },
            x: {
                grid: { color: "rgba(143, 168, 199, 0.09)" },
                ticks: { color: "#8fa8c7" }
            }
        }
    };
}

function resizeCharts() {
    setTimeout(() => {
        ppsChart?.resize();
        latencyChart?.resize();
        resizeServerGlobe();
    }, 60);
}

function normalizeGeoPoints(points) {
    return points
        .filter((point) => Number.isFinite(Number(point.lat)) && Number.isFinite(Number(point.lon)))
        .map((point) => ({
            ...point,
            protocol: currentProto,
            lat: Number(point.lat),
            lon: Number(point.lon),
            entryCount: Array.isArray(point.entries) ? point.entries.length : 1
        }));
}

function renderGeoUnresolved(items) {
    const container = document.getElementById("geoUnresolvedList");
    if (!container) return;
    if (!items.length) {
        container.classList.remove("active");
        container.innerHTML = "";
        return;
    }
    const preview = items.slice(0, 5)
        .map((item) => `${escapeHtml(item.entry || item.ip || "-")} (${escapeHtml(formatGeoReason(item.reason))})`)
        .join(" · ");
    const suffix = items.length > 5 ? ` · 另有 ${items.length - 5} 个未显示` : "";
    container.classList.add("active");
    container.innerHTML = `<strong>未定位：</strong>${preview}${suffix}`;
}

function setMapStatus(message, loading = false, hide = false) {
    const status = document.getElementById("serverGlobeStatus");
    if (!status) return;
    status.classList.toggle("hidden", hide);
    status.innerText = message;
    status.style.borderLeft = loading ? "4px solid var(--cyan)" : "1px solid rgba(143, 168, 199, 0.2)";
}

function initServerGlobe() {
    const container = document.getElementById("serverGlobe");
    if (!container) return;
    if (!window.Globe) {
        setMapStatus("3D 地图库加载失败，仍可切换 2D 查看资源区域。", false);
        return;
    }
    serverGlobe = window.Globe()(container)
        .backgroundColor("rgba(0,0,0,0)")
        .globeImageUrl("//unpkg.com/three-globe/example/img/earth-blue-marble.jpg")
        .bumpImageUrl("//unpkg.com/three-globe/example/img/earth-topology.png")
        .polygonsData([])
        .polygonAltitude(() => 0.004)
        .polygonCapColor((feature) => getAreaFillColor(feature.properties?._resourceArea))
        .polygonSideColor(() => "rgba(64, 231, 255, 0.08)")
        .polygonStrokeColor(() => "rgba(223, 245, 255, 0.78)")
        .polygonLabel((feature) => renderAreaTooltip(feature.properties?._resourceArea));
    const controls = serverGlobe.controls();
    if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.35;
        controls.enableDamping = true;
    }
    resizeServerGlobe();
}

function resizeServerGlobe() {
    renderServerMap();
}

function resizeServerMapSurface() {
    const container = document.getElementById("serverGlobe");
    if (!container || !serverGlobe) return;
    const width = Math.max(280, container.clientWidth);
    const height = Math.max(300, container.clientHeight);
    serverGlobe.width(width).height(height);
}

async function loadServerGeoMap() {
    if (isGeoMapLoading) return;
    isGeoMapLoading = true;
    setMapStatus("正在定位资源池 IP...", true);
    try {
        const response = await fetch(`/api/servers/${currentProto}/geo`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "定位失败");
        updateGeoStats(data);
        renderGeoUnresolved(data.unresolved || []);
        lastGeoPoints = normalizeGeoPoints(data.points || []);
        lastGeoAreas = normalizeGeoAreas(data.areas || []);
        await ensureServerMapShapes();
        renderServerMap();
        if (!window.Globe) {
            setMapStatus("3D 地图库加载失败，已保留资源区域统计。", false);
        } else if (data.geo_api_degraded) {
            setMapStatus("GeoIP 服务暂不可用，地图已使用可用缓存和已解析数据。", false);
        } else if (!lastGeoAreas.length) {
            setMapStatus("当前资源池没有可显示的国家或省份区域。", false);
        } else {
            setMapStatus(`已显示 ${lastGeoAreas.length} 个资源归属区域。`, false, true);
        }
    } catch (error) {
        updateGeoStats({ total: 0, located_count: 0, unresolved_count: 0, area_count: 0 });
        renderGeoUnresolved([]);
        setMapStatus(`地图定位失败：${error.message}`, false);
    } finally {
        isGeoMapLoading = false;
        renderServerMap();
    }
}

function normalizeGeoAreas(areas) {
    return areas.map((area) => ({
        ...area,
        protocol: currentProto,
        resource_count: Number(area.resource_count || 0),
        entries: Array.isArray(area.entries) ? area.entries : [],
        ips: Array.isArray(area.ips) ? area.ips : []
    }));
}

function updateGeoStats(data) {
    setText("geoTotalCount", String(data.total || 0));
    setText("geoLocatedCount", String(data.located_count || 0));
    setText("geoUnresolvedCount", String(data.unresolved_count || 0));
    setText("geoAreaCount", String(data.area_count || 0));
}

async function ensureServerMapShapes() {
    if (serverMapShapes) return serverMapShapes;
    const [countries, admin1, china] = await Promise.all([
        fetch("/static/maps/countries.geojson").then((response) => response.json()),
        fetch("/static/maps/admin1.geojson").then((response) => response.json()),
        fetch("/static/maps/china-provinces.geojson").then((response) => response.json())
    ]);
    serverMapShapes = { countries, admin1, china };
    return serverMapShapes;
}

function switchServerMapMode(mode) {
    serverMapMode = mode === "2d" ? "2d" : "3d";
    document.querySelectorAll(".map-view-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.mapView === serverMapMode);
    });
    renderServerMap();
}

function renderServerMap() {
    const globe = document.getElementById("serverGlobe");
    const map2d = document.getElementById("serverMap2d");
    if (globe) globe.hidden = serverMapMode !== "3d";
    if (map2d) map2d.hidden = serverMapMode !== "2d";
    const features = buildAreaFeatures();
    if (serverMapMode === "3d") renderServerMap3d(features);
    if (serverMapMode === "2d") renderServerMap2d(features);
}

function renderServerMap3d(features) {
    resizeServerMapSurface();
    if (!serverGlobe) return;
    serverGlobe.polygonsData(features.map(normalizeFeatureForGlobe));
    const first = lastGeoPoints.find((point) => Number.isFinite(point.lat) && Number.isFinite(point.lon));
    if (first) serverGlobe.pointOfView({ lat: first.lat, lng: first.lon, altitude: 2.1 }, 700);
}

function renderServerMap2d(features) {
    const svg = document.getElementById("serverMap2dSvg");
    const container = document.getElementById("serverMap2d");
    if (!svg || !container || !window.d3 || !serverMapShapes) return;
    const normalizedFeatures = features.map(normalizeFeatureForGlobe);
    const width = Math.max(280, container.clientWidth);
    const height = Math.max(300, container.clientHeight);
    const selection = d3.select(svg);
    selection.attr("viewBox", `0 0 ${width} ${height}`).selectAll("*").remove();

    const projection = d3.geoNaturalEarth1().fitSize([width, height], serverMapShapes.countries);
    const path = d3.geoPath(projection);
    const zoomLayer = selection.append("g").attr("class", "map-zoom-layer");
    const initialTransform = serverMap2dZoomTransform || d3.zoomIdentity;

    zoomLayer.append("g")
        .selectAll("path")
        .data(serverMapShapes.countries.features || [])
        .join("path")
        .attr("class", "map-base")
        .attr("d", path);

    zoomLayer.append("g")
        .selectAll("path")
        .data(normalizedFeatures)
        .join("path")
        .attr("class", "map-area")
        .attr("d", path)
        .attr("fill", (feature) => getAreaFillColor(feature.properties?._resourceArea))
        .append("title")
        .text((feature) => getAreaTooltipText(feature.properties?._resourceArea));

    zoomLayer.attr("transform", initialTransform);
    const zoom = d3.zoom()
        .scaleExtent([1, 9])
        .extent([[0, 0], [width, height]])
        .translateExtent([[-width * 0.5, -height * 0.5], [width * 1.5, height * 1.5]])
        .on("zoom", (event) => {
            serverMap2dZoomTransform = event.transform;
            zoomLayer.attr("transform", serverMap2dZoomTransform);
        });
    selection.call(zoom).call(zoom.transform, initialTransform).on("dblclick.zoom", null);
}

function buildAreaFeatures() {
    if (!serverMapShapes || !lastGeoAreas.length) return [];
    return lastGeoAreas
        .map((area) => {
            const feature = findAreaFeature(area);
            if (!feature) return null;
            return {
                ...feature,
                properties: {
                    ...(feature.properties || {}),
                    _resourceArea: area
                }
            };
        })
        .filter(Boolean);
}

function normalizeFeatureForGlobe(feature) {
    const clone = {
        ...feature,
        properties: { ...(feature.properties || {}) },
        geometry: {
            ...(feature.geometry || {}),
            coordinates: JSON.parse(JSON.stringify(feature.geometry?.coordinates || []))
        }
    };
    if (clone.geometry.type === "Polygon") {
        clone.geometry.coordinates = normalizePolygonRingsForGlobe(clone.geometry.coordinates);
    }
    if (clone.geometry.type === "MultiPolygon") {
        clone.geometry.coordinates = clone.geometry.coordinates.map(normalizePolygonRingsForGlobe);
    }
    return clone;
}

function normalizePolygonRingsForGlobe(rings) {
    return rings.map((ring, index) => {
        const shouldBeClockwise = index === 0;
        const isClockwise = getRingSignedArea(ring) < 0;
        return shouldBeClockwise === isClockwise ? ring : [...ring].reverse();
    });
}

function getRingSignedArea(ring) {
    let area = 0;
    for (let index = 0; index < ring.length; index += 1) {
        const current = ring[index];
        const next = ring[(index + 1) % ring.length];
        area += Number(current?.[0] || 0) * Number(next?.[1] || 0)
            - Number(next?.[0] || 0) * Number(current?.[1] || 0);
    }
    return area / 2;
}

function findAreaFeature(area) {
    if (area.level === "region") {
        if (area.country_code === "CN") return findChinaRegionFeature(area);
        const areaCode = String(area.area_code || "").toUpperCase();
        const regionCode = String(area.region_code || "").toUpperCase();
        return (serverMapShapes.admin1.features || []).find((feature) => {
            const props = feature.properties || {};
            return String(props.iso_3166_2 || "").toUpperCase() === areaCode
                || (String(props.iso_a2 || "").toUpperCase() === area.country_code && String(props.postal || "").toUpperCase() === regionCode);
        }) || findCountryFeature(area.country_code);
    }
    return findCountryFeature(area.country_code);
}

function findChinaRegionFeature(area) {
    const regionCode = String(area.region_code || "").toUpperCase();
    const adcode = CHINA_REGION_ADCODE[regionCode];
    const regionName = String(area.region || "").toLowerCase();
    return (serverMapShapes.china.features || []).find((feature) => {
        const props = feature.properties || {};
        return (adcode && String(props.adcode) === adcode)
            || (regionName && String(props.name || "").toLowerCase().includes(regionName));
    }) || findCountryFeature("CN");
}

function findCountryFeature(countryCode) {
    const code = String(countryCode || "").toUpperCase();
    return (serverMapShapes.countries.features || []).find((feature) => {
        const props = feature.properties || {};
        return String(props.ISO_A2 || props.iso_a2 || "").toUpperCase() === code;
    });
}

function getAreaFillColor(area) {
    const count = Number(area?.resource_count || 0);
    const max = Math.max(1, ...lastGeoAreas.map((item) => Number(item.resource_count || 0)));
    const ratio = Math.log1p(count) / Math.log1p(max);
    const base = {
        memcached: [157, 92, 255],
        dns: [64, 231, 255],
        ntp: [92, 255, 177]
    }[area?.protocol || currentProto] || [64, 231, 255];
    const alpha = 0.28 + ratio * 0.5;
    return `rgba(${base[0]}, ${base[1]}, ${base[2]}, ${alpha.toFixed(2)})`;
}

function renderAreaTooltip(area) {
    return `<div class="globe-tooltip">${escapeHtml(getAreaTooltipText(area)).replace(/\n/g, "<br>")}</div>`;
}

function getAreaTooltipText(area) {
    if (!area) return "未知区域";
    const name = area.level === "region"
        ? `${area.country || "-"} / ${area.region || area.name || "-"}`
        : `${area.country || area.name || "-"}`;
    const samples = (area.ips || []).slice(0, 5).join(", ");
    const suffix = (area.ips || []).length > 5 ? `，另有 ${(area.ips || []).length - 5} 个 IP` : "";
    return [
        name,
        `协议：${getMethodText(area.protocol)}`,
        `资源数：${area.resource_count || 0}`,
        samples ? `IP：${samples}${suffix}` : ""
    ].filter(Boolean).join("\n");
}

function formatGeoReason(reason) {
    return {
        empty: "空条目",
        dns_failed: "域名解析失败",
        invalid_ip: "无效 IP",
        private_or_reserved: "非公网地址",
        geo_not_found: "无定位结果",
        geo_api_failed: "定位服务失败"
    }[reason] || reason || "未知原因";
}

function addChartData(pps) {
    if (!ppsChart) return;
    ppsDataPoints.push(pps);
    if (ppsDataPoints.length > MAX_PPS_POINTS) ppsDataPoints.shift();
    ppsChart.data.labels = ppsDataPoints.map((_, index) => index + 1);
    ppsChart.data.datasets[0].data = [...ppsDataPoints];
    ppsChart.update("none");
}

function resetChart() {
    ppsDataPoints = [];
    if (!ppsChart) return;
    ppsChart.data.labels = [];
    ppsChart.data.datasets[0].data = [];
    ppsChart.update();
}

function initProtocolCheckboxes() {
    document.querySelectorAll("#multiProtocolSection input[type='checkbox']").forEach((checkbox) => {
        checkbox.addEventListener("change", updateProtocolSelection);
    });
    updateProtocolSelection();
}

function toggleMultiProtocol() {
    const toggle = document.getElementById("multi_protocol");
    const singleGroup = document.getElementById("singleMethodGroup");
    const multiSection = document.getElementById("multiProtocolSection");
    isMultiProtocol = Boolean(toggle?.checked);
    if (singleGroup) singleGroup.style.display = isMultiProtocol ? "none" : "block";
    if (multiSection) multiSection.style.display = isMultiProtocol ? "block" : "none";
    updateProtocolSelection();
}

function updateMethodSettings() {
    const method = document.getElementById("method")?.value;
    if (method) loadReflectorCount([method]);
}

function updateProtocolSelection() {
    selectedProtocols = Array.from(document.querySelectorAll("#multiProtocolSection input[type='checkbox']:checked"))
        .map((input) => input.value);
    if (isMultiProtocol) {
        loadReflectorCount(selectedProtocols);
    } else {
        const method = document.getElementById("method")?.value;
        loadReflectorCount(method ? [method] : ["memcached", "dns", "ntp"]);
    }
}

async function loadReflectorCount(protocols) {
    const countEl = document.getElementById("reflectors_count");
    if (!countEl || !protocols.length) {
        if (countEl) countEl.innerText = "0";
        return;
    }
    try {
        const data = await postJson("/api/servers/count", { protocols });
        if (data.success) {
            countEl.innerText = String(data.total_count || 0);
        }
    } catch (error) {
        countEl.innerText = "0";
    }
}

function loadAllServerCounts() {
    loadReflectorCount(["memcached", "dns", "ntp"]);
}

async function loadServerListForEdit() {
    const editor = document.getElementById("serverListEditor");
    if (!editor) return;
    try {
        const response = await fetch(`/api/servers/${currentProto}/list`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "加载失败");
        editor.value = (data.servers || []).join("\n");
    } catch (error) {
        showNotification(`资源列表加载失败：${error.message}`, "error");
    }
}

function refreshServerResources() {
    loadServerListForEdit();
    loadServerGeoMap();
}

async function saveServerList() {
    const editor = document.getElementById("serverListEditor");
    if (!editor) return;
    const servers = editor.value
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"));
    try {
        const data = await postJson(`/api/servers/${currentProto}/update`, { servers });
        if (!data.success) throw new Error(data.message || "保存失败");
        showNotification(data.message || "资源列表已保存", "success");
        loadAllServerCounts();
        loadServerGeoMap();
    } catch (error) {
        showNotification(`保存失败：${error.message}`, "error");
    }
}

async function startTest() {
    const targetIpInput = document.getElementById("target_ip");
    const targetIp = targetIpInput?.value.trim() || "";
    if (!targetIp) {
        showNotification("请输入目标 IP", "error");
        return;
    }
    if (!validateIpAddress(targetIpInput)) {
        showNotification("IP 格式无效", "error");
        return;
    }

    const data = {
        target_ip: targetIp,
        target_port: readNumber("target_port", 80),
        duration: readNumber("duration", 5),
        threads: readNumber("threads", 8),
        target_pps: readNumber("target_pps", 5000),
        multi_protocol: isMultiProtocol
    };

    if (isMultiProtocol) {
        updateProtocolSelection();
        if (!selectedProtocols.length) {
            showNotification("请至少选择一个协议", "error");
            return;
        }
        data.selected_protocols = selectedProtocols;
        data.method = selectedProtocols[0];
    } else {
        const method = document.getElementById("method")?.value;
        if (!method) {
            showNotification("请选择测试协议", "error");
            return;
        }
        data.method = method;
        data.selected_protocols = [method];
    }

    syncLatencyTarget(data.target_ip, data.target_port);
    resetLatencyBaseline();
    attackStartTimeForLatency = Date.now() / 1000;
    if (!isMonitoringLatency) startLatencyMonitoring();

    setRunningControls(true);
    resetChart();

    try {
        const result = await postJson("/api/test/start", data);
        if (!result.success) throw new Error(result.message || "启动失败");
        showNotification("测试已启动", "success");
        setStatusTag("running", "运行中");
    } catch (error) {
        showNotification(`启动失败：${error.message}`, "error");
        setRunningControls(false);
    }
}

async function stopTest() {
    try {
        const result = await postJson("/api/test/stop", {});
        showNotification(result.message || "正在停止测试", result.success ? "info" : "error");
    } catch (error) {
        showNotification(`停止失败：${error.message}`, "error");
    } finally {
        setRunningControls(false);
        setStatusTag("stopping", "停止中");
    }
}

async function resetTest() {
    try {
        await postJson("/api/test/reset", {});
        showNotification("系统已重置", "info");
    } catch (error) {
        showNotification(`重置失败：${error.message}`, "error");
    }
    setRunningControls(false);
    setStatusTag("idle", "待命中");
    resetChart();
    stopLatencyMonitoring(false);
    resetLatencyBaseline();
    latencyDataPoints = [];
    if (latencyChart) {
        latencyChart.data.labels = [];
        latencyChart.data.datasets[0].data = [];
        latencyChart.update();
    }
    setText("victimInfo", "未指定");
    setText("modeInfo", "单协议");
    setText("methodInfo", "-");
    setText("sendPps", "0");
    setText("bandwidth", "0");
    setText("amplification", "0");
    setText("efficiency", "0");
    setText("progressDetail", "0%");
    const progressBar = document.getElementById("progressBar");
    if (progressBar) progressBar.style.width = "0%";
    const protocolStats = document.getElementById("protocolStatsSection");
    if (protocolStats) protocolStats.style.display = "none";
}

function pollStatus() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(async () => {
        try {
            const response = await fetch("/api/config");
            const status = await response.json();
            updateStatusDisplay(status);
        } catch (error) {
            console.warn("状态轮询失败", error);
        }
    }, 1000);
}

function updateStatusDisplay(status) {
    if (!status) return;
    if (status.status === "running") {
        setStatusTag("running", "运行中");
        setRunningControls(true);
    } else if (status.status === "stopping") {
        setStatusTag("stopping", "停止中");
        setRunningControls(true, true);
    } else if (status.status === "error") {
        setStatusTag("stopping", "异常");
        setRunningControls(false);
    } else {
        setStatusTag("idle", "待命中");
        setRunningControls(false);
    }

    const pps = Math.round(status.current_pps || 0);
    const mbps = Number(status.current_mbps || 0);
    const victimMbps = Number(status.victim_mbps || 0);
    const amplification = victimMbps > 0 || mbps > 0 ? victimMbps / Math.max(mbps, 1) : 0;
    const expected = Number(status.expected_amplification || 10);
    const efficiency = expected > 0 ? Math.min(999, (amplification / expected) * 100) : 0;
    const progress = Math.max(0, Math.min(100, Number(status.progress_percent || 0)));

    setText("sendPps", pps.toLocaleString());
    setText("bandwidth", mbps.toFixed(1));
    setText("amplification", amplification.toFixed(1));
    setText("efficiency", efficiency.toFixed(0));
    setText("progressDetail", `${Math.round(progress)}%`);

    const progressBar = document.getElementById("progressBar");
    if (progressBar) progressBar.style.width = `${progress}%`;

    if (status.config) {
        setText("victimInfo", `${status.config.target_ip}:${status.config.target_port}`);
        setText("modeInfo", status.config.method === "multi" ? "多协议" : "单协议");
        if (status.config.method === "multi" && status.config.multi_protocols) {
            setText("methodInfo", status.config.multi_protocols.map(getMethodText).join(" + "));
        } else if (status.config.single_method) {
            setText("methodInfo", getMethodText(status.config.single_method));
        } else {
            setText("methodInfo", "-");
        }
    }

    if (pps > 0) addChartData(pps);
    renderProtocolStats(status);
}

function renderProtocolStats(status) {
    const section = document.getElementById("protocolStatsSection");
    const grid = document.getElementById("protocolStatsGrid");
    if (!section || !grid) return;

    const protocols = status.config?.method === "multi" ? (status.config.multi_protocols || []) : [];
    if (!protocols.length) {
        section.style.display = "none";
        grid.innerHTML = "";
        return;
    }

    const protoDetails = status.protocol_details || {};
    section.style.display = "block";
    grid.innerHTML = "";
    protocols.forEach((proto) => {
        const stats = protoDetails[proto] || {};
        const card = document.createElement("div");
        card.className = "protocol-stat-card";
        const iconClass = proto === "memcached" ? "fa-database" : proto === "dns" ? "fa-globe" : "fa-clock";
        card.innerHTML = `
            <div class="protocol-stat-header">
                <div class="protocol-icon" style="background:${getProtocolColor(proto)}"><i class="fas ${iconClass}"></i></div>
                <span class="protocol-stat-name">${getMethodText(proto)}</span>
            </div>
            <div class="protocol-stat-values">
                <div>速率：${Math.round(stats.current_pps || 0).toLocaleString()} pps</div>
                <div>带宽：${Number(stats.current_mbps || 0).toFixed(1)} Mbps</div>
                <div>包数：${Number(stats.packets_sent || 0).toLocaleString()}</div>
            </div>
        `;
        grid.appendChild(card);
    });
}

async function updateSystemInfo() {
    try {
        const response = await fetch("/api/system/info");
        const data = await response.json();
        if (!data.success) return;
        setText("cpuUsage", `${Math.round(data.cpu_percent || 0)}%`);
        setText("memUsage", `${Math.round(data.memory?.percent || 0)}%`);
    } catch (error) {
        console.warn("系统信息更新失败", error);
    }
}

async function updateDetailedSystemInfo() {
    try {
        const response = await fetch("/api/system/info");
        const data = await response.json();
        if (!data.success) return;
        setText("cpuDetail", `${Number(data.cpu_percent || 0).toFixed(1)}%`);
        setText("memDetail", `${Number(data.memory?.percent || 0).toFixed(1)}%`);
        setText("memUsedDetail", `${(Number(data.memory?.used || 0) / 1024 / 1024).toFixed(0)}`);
        setText("memTotalDetail", `${(Number(data.memory?.total || 0) / 1024 / 1024).toFixed(0)}`);
        setText("netSent", `${(Number(data.network?.bytes_sent || 0) / 1024 / 1024).toFixed(1)}`);
        setText("netRecv", `${(Number(data.network?.bytes_recv || 0) / 1024 / 1024).toFixed(1)}`);
    } catch (error) {
        console.warn("系统资源更新失败", error);
    }
}

async function measureLatency() {
    const target = document.getElementById("latencyTargetIp")?.value.trim()
        || document.getElementById("target_ip")?.value.trim();
    const port = readNumber("latencyPort", 80);
    if (!target) return null;
    try {
        const data = await postJson("/api/tcping", { target, port, timeout: 3 });
        return data.success ? data.latency : null;
    } catch (error) {
        return null;
    }
}

async function startLatencyMonitoring() {
    if (latencyMonitorInterval) clearInterval(latencyMonitorInterval);
    isMonitoringLatency = true;
    isLatencySamplePending = false;
    if (!attackStartTimeForLatency) attackStartTimeForLatency = Date.now() / 1000;
    latencyDataPoints = [];
    if (latencyChart) {
        latencyChart.data.labels = [];
        latencyChart.data.datasets[0].data = [];
        latencyChart.update();
    }
    showNotification("延迟监控已启动", "info");

    sampleLatencyOnce();
    latencyMonitorInterval = setInterval(sampleLatencyOnce, 1000);
}

function stopLatencyMonitoring(showMessage = true) {
    isMonitoringLatency = false;
    if (latencyMonitorInterval) {
        clearInterval(latencyMonitorInterval);
        latencyMonitorInterval = null;
    }
    isLatencySamplePending = false;
    if (showMessage) showNotification("延迟监控已停止", "info");
}

function resetLatencyBaseline() {
    baselineLatency = null;
    baselineSamples = [];
    setText("autoPingBefore", "-- ms");
    setText("latestLatency", "-- ms");
    setText("latencyTrend", "--");
}

function syncLatencyTarget(ip, port) {
    const latencyTarget = document.getElementById("latencyTargetIp");
    const latencyPort = document.getElementById("latencyPort");
    if (latencyTarget) latencyTarget.value = ip;
    if (latencyPort) latencyPort.value = port;
}

function updateLatencyDisplay(latency, isTimeout = false) {
    const latest = document.getElementById("latestLatency");
    const trend = document.getElementById("latencyTrend");
    if (!latest || !trend) return;

    if (isTimeout) {
        latest.innerText = "超时";
        latest.style.color = "#ff4f6d";
        trend.innerText = "连接超时";
        trend.style.color = "#ff4f6d";
        return;
    }

    latest.innerText = `${latency} ms`;
    latest.style.color = "#5cffb1";
    if (baselineLatency === null) {
        trend.innerText = "--";
        trend.style.color = "#ffbd5c";
        return;
    }
    const diff = latency - baselineLatency;
    trend.innerText = `${diff >= 0 ? "+" : "-"}${Math.abs(diff).toFixed(2)} ms`;
    trend.style.color = diff > 0 ? "#ffbd5c" : "#5cffb1";
}

async function sampleLatencyOnce() {
    if (!isMonitoringLatency || isLatencySamplePending) return;
    isLatencySamplePending = true;
    try {
        const latency = await measureLatency();
        if (latency === null) {
            updateLatencyDisplay(null, true);
            addLatencyDataPoint(null);
            return;
        }
        updateLatencyDisplay(latency, false);
        addLatencyDataPoint(latency);
        if (baselineLatency === null && baselineSamples.length < 3) {
            baselineSamples.push(latency);
            if (baselineSamples.length === 3) {
                baselineLatency = baselineSamples.reduce((sum, item) => sum + item, 0) / 3;
                setText("autoPingBefore", `${baselineLatency.toFixed(2)} ms`);
            }
        }
    } finally {
        isLatencySamplePending = false;
    }
}

function addLatencyDataPoint(latency) {
    if (!latencyChart) return;
    const elapsed = attackStartTimeForLatency
        ? Math.max(0, Math.round(Date.now() / 1000 - attackStartTimeForLatency))
        : latencyDataPoints.length + 1;
    latencyDataPoints.push({ label: String(elapsed), value: latency });
    if (latencyDataPoints.length > MAX_LATENCY_POINTS) latencyDataPoints.shift();
    latencyChart.data.labels = latencyDataPoints.map((point) => point.label);
    latencyChart.data.datasets[0].data = latencyDataPoints.map((point) => point.value);
    latencyChart.update("none");
}

function validateIpAddress(input) {
    if (!input) return false;
    const pattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    const isValid = pattern.test(input.value.trim());
    input.style.borderColor = isValid ? "#40e7ff" : "#ff4f6d";
    return isValid;
}

async function postJson(url, payload) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    const data = await readJsonResponse(response);
    if (!response.ok) {
        throw new Error(data?.message || data?.error || `HTTP ${response.status}`);
    }
    return data ?? {};
}

async function readJsonResponse(response) {
    const contentType = response.headers.get("Content-Type") || "";
    if (!contentType.includes("application/json")) return null;
    try {
        return await response.json();
    } catch (error) {
        return null;
    }
}

function readNumber(id, fallback) {
    const value = Number(document.getElementById(id)?.value);
    return Number.isFinite(value) && value > 0 ? value : fallback;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.innerText = value;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function setRunningControls(isRunning, isStopping = false) {
    const startBtn = document.getElementById("startBtn");
    const stopBtn = document.getElementById("stopBtn");
    if (startBtn) startBtn.disabled = isRunning;
    if (stopBtn) stopBtn.disabled = !isRunning || isStopping;
}

function setStatusTag(state, text) {
    const tag = document.getElementById("attackModeTag");
    if (!tag) return;
    tag.classList.remove("running", "stopping");
    if (state === "running") tag.classList.add("running");
    if (state === "stopping") tag.classList.add("stopping");
    tag.innerText = text;
}

function getMethodText(method) {
    return {
        memcached: "Memcached",
        dns: "DNS",
        ntp: "NTP"
    }[method] || method || "-";
}

function getProtocolColor(protocol) {
    return {
        memcached: "linear-gradient(135deg, #7c8cff 0%, #9d5cff 100%)",
        dns: "linear-gradient(135deg, #40e7ff 0%, #2d8cff 100%)",
        ntp: "linear-gradient(135deg, #5cffb1 0%, #1fbf75 100%)"
    }[protocol] || "linear-gradient(135deg, #40e7ff 0%, #2d8cff 100%)";
}

function showNotification(message, type = "info") {
    const notif = document.createElement("div");
    notif.className = `notification ${type}`;
    notif.innerHTML = `<span>${message}</span><button type="button" aria-label="关闭通知">×</button>`;
    notif.querySelector("button")?.addEventListener("click", () => notif.remove());
    document.body.appendChild(notif);
    setTimeout(() => notif.remove(), 3200);
}

function initParticles() {
    const canvas = document.getElementById("particleCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let width = 0;
    let height = 0;
    let particles = [];
    const count = 90;

    function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
        particles = Array.from({ length: count }, () => ({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.24,
            vy: (Math.random() - 0.5) * 0.24,
            r: Math.random() * 1.6 + 0.6,
            a: Math.random() * 0.35 + 0.12
        }));
        resizeCharts();
    }

    function draw() {
        ctx.clearRect(0, 0, width, height);
        particles.forEach((p) => {
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0) p.x = width;
            if (p.x > width) p.x = 0;
            if (p.y < 0) p.y = height;
            if (p.y > height) p.y = 0;
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(64, 231, 255, ${p.a})`;
            ctx.fill();
        });
        requestAnimationFrame(draw);
    }

    window.addEventListener("resize", resize);
    resize();
    draw();
}
