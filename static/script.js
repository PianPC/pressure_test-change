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
let isGeoMapLoading = false;

const MAX_PPS_POINTS = 40;
const MAX_LATENCY_POINTS = 60;

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
    pollStatus();
    updateSystemInfo();
    updateDetailedSystemInfo();
    setInterval(updateSystemInfo, 3000);
    setInterval(updateDetailedSystemInfo, 2000);
});

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
            resizeCharts();
        });
    });
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

function initServerGlobe() {
    const container = document.getElementById("serverGlobe");
    if (!container) return;
    if (!window.Globe) {
        setMapStatus("3D 地图库加载失败，仍可继续编辑资源列表。", false);
        return;
    }
    serverGlobe = window.Globe()(container)
        .backgroundColor("rgba(0,0,0,0)")
        .globeImageUrl("//unpkg.com/three-globe/example/img/earth-blue-marble.jpg")
        .bumpImageUrl("//unpkg.com/three-globe/example/img/earth-topology.png")
        .pointsData([])
        .pointLat((point) => point.lat)
        .pointLng((point) => point.lon)
        .pointAltitude((point) => Math.max(0.035, Math.min(0.18, 0.035 + (point.entryCount || 1) * 0.01)))
        .pointRadius((point) => Math.max(0.32, Math.min(0.9, 0.32 + (point.entryCount || 1) * 0.08)))
        .pointColor((point) => getProtocolPointColor(point.protocol))
        .pointLabel((point) => renderGeoTooltip(point));
    const controls = serverGlobe.controls();
    if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.35;
        controls.enableDamping = true;
    }
    resizeServerGlobe();
}

function resizeServerGlobe() {
    if (!serverGlobe) return;
    const container = document.getElementById("serverGlobe");
    if (!container) return;
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
        if (serverGlobe) {
            serverGlobe.pointsData(lastGeoPoints);
            if (lastGeoPoints.length) serverGlobe.pointOfView({ lat: lastGeoPoints[0].lat, lng: lastGeoPoints[0].lon, altitude: 2.1 }, 900);
        }
        if (!window.Globe) {
            setMapStatus("3D 地图库加载失败，已保留资源定位统计。", false);
        } else if (data.geo_api_degraded) {
            setMapStatus("GeoIP 服务暂不可用，地图已使用可用缓存和已解析数据。", false);
        } else if (!lastGeoPoints.length) {
            setMapStatus("当前资源池没有可定位的公网 IP。", false);
        } else {
            setMapStatus(`已定位 ${lastGeoPoints.length} 个公网 IP。`, false, true);
        }
    } catch (error) {
        updateGeoStats({ total: 0, located_count: 0, unresolved_count: 0 });
        renderGeoUnresolved([]);
        setMapStatus(`地图定位失败：${error.message}`, false);
    } finally {
        isGeoMapLoading = false;
        resizeServerGlobe();
    }
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

function updateGeoStats(data) {
    setText("geoTotalCount", String(data.total || 0));
    setText("geoLocatedCount", String(data.located_count || 0));
    setText("geoUnresolvedCount", String(data.unresolved_count || 0));
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

function renderGeoTooltip(point) {
    const location = [point.city, point.country].filter(Boolean).join(", ") || "未知位置";
    const aliases = Array.isArray(point.entries) && point.entries.length > 1
        ? `<div>资源条目：${point.entries.map(escapeHtml).join(", ")}</div>`
        : "";
    return `
        <div class="globe-tooltip">
            <strong>${escapeHtml(point.ip)}</strong>
            <div>${escapeHtml(location)}</div>
            <div>${escapeHtml(point.isp || "未知 ISP")}</div>
            ${aliases}
        </div>
    `;
}

function getProtocolPointColor(protocol) {
    return {
        memcached: "#9d5cff",
        dns: "#40e7ff",
        ntp: "#5cffb1"
    }[protocol] || "#40e7ff";
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
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
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
