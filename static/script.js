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
let serverUnresolvedCount = 0;
let selectedAreaCode = "";
let selectedIp = "";
let serverListFilterMode = "all";
let currentServerFile = null;
let currentServerSource = "";
let currentServerEditorProto = "";
let availableServerSourcesByProto = {};
let selectedServerSourcesByProto = {};
let multiProtoSelectedSources = {};  // 多协议模式下每个协议的源文件选择
let singleSelectedSources = [];       // 单协议模式下选择的源文件列表
let serverSourceModalProto = "";      // 当前 source modal 打开的协议
let tcpScanPollInterval = null;
let currentTcpRunId = null;
let currentTcpRuns = [];
let currentTcpFile = null;
let currentDnsFile = null;
let currentNtpFile = null;
let currentAttackResourceProto = "tcp";
let currentView = "dashboard";
let lastVisitedWorkflowStep = "resource";
let latestStatusSnapshot = null;
let currentTcpSummary = null;
let attackResourceTaskFrameworkInitialized = false;
let currentAttackResourceFile = null;
const attackResourceControllers = {};

let ipResourceListCache = [];
let ipResourceFilterCache = {};
let currentEditingResourcePath = null;
let ipResourceSources = [];
let ipResourceCountries = [];

const IPResourceManager = (() => {
    function getApiUrl(endpoint) {
        return `/api/attack-resource${endpoint}`;
    }

    async function fetchResources(filters = {}) {
        const params = new URLSearchParams();
        if (filters.type) params.set('type', filters.type);
        if (filters.source) params.set('source', filters.source);
        if (filters.country) params.set('country', filters.country);
        if (filters.protocol) params.set('protocol', filters.protocol);

        const resp = await fetch(`${getApiUrl('/resources')}?${params.toString()}`);
        const data = await resp.json();
        if (data.success) {
            ipResourceListCache = data.resources;
            ipResourceFilterCache = data.filters;
            return data;
        }
        throw new Error(data.message || '获取资源失败');
    }

    async function fetchSources() {
        const resp = await fetch(getApiUrl('/resources/sources'));
        const data = await resp.json();
        if (data.success) {
            ipResourceSources = data.sources;
            return data.sources;
        }
        return [];
    }

    async function fetchCountries() {
        const resp = await fetch(getApiUrl('/resources/countries'));
        const data = await resp.json();
        if (data.success) {
            ipResourceCountries = data.countries;
            return data.countries;
        }
        return [];
    }

    async function readResource(path) {
        const encodedPath = path.split('/').map(encodeURIComponent).join('/');
        const resp = await fetch(getApiUrl(`/resources/${encodedPath}`));
        const data = await resp.json();
        if (data.success) {
            return data.resource;
        }
        throw new Error(data.message || '读取资源失败');
    }

    async function writeResource(path, content) {
        const encodedPath = path.split('/').map(encodeURIComponent).join('/');
        const resp = await fetch(getApiUrl(`/resources/${encodedPath}`), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        const data = await resp.json();
        if (data.success) {
            return data.resource;
        }
        throw new Error(data.message || '写入资源失败');
    }

    async function createResource(filename, content) {
        const resp = await fetch(getApiUrl('/resources'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename, content })
        });
        const data = await resp.json();
        if (data.success) {
            return data.resource;
        }
        throw new Error(data.message || '创建资源失败');
    }

    async function deleteResource(path) {
        const encodedPath = path.split('/').map(encodeURIComponent).join('/');
        const resp = await fetch(getApiUrl(`/resources/${encodedPath}`), {
            method: 'DELETE'
        });
        const data = await resp.json();
        if (data.success) {
            return true;
        }
        throw new Error(data.message || '删除资源失败');
    }

    async function fetchAutoResources(spiderName, params) {
        const resp = await fetch(getApiUrl('/resources/fetch'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spider: spiderName, params })
        });
        const data = await resp.json();
        return data;
    }

    return {
        fetchResources,
        fetchSources,
        fetchCountries,
        readResource,
        writeResource,
        createResource,
        deleteResource,
        fetchAutoResources
    };
})();

const IPResourceUi = (() => {
    function openManageModal() {
        document.getElementById('ipResourceModal').hidden = false;
        loadResourceList();
    }

    function closeManageModal() {
        document.getElementById('ipResourceModal').hidden = true;
    }

    async function loadResourceList() {
        const filters = {
            type: document.getElementById('ipResourceFilterType').value,
            source: document.getElementById('ipResourceFilterSource').value,
            country: document.getElementById('ipResourceFilterCountry').value,
            protocol: document.getElementById('ipResourceFilterProtocol').value
        };

        try {
            const data = await IPResourceManager.fetchResources(filters);
            renderResourceList(data.resources);
            updateFilterDropdowns(data.filters);
        } catch (e) {
            console.error('加载资源列表失败:', e);
        }
    }

    function renderResourceList(resources) {
        const listEl = document.getElementById('ipResourceList');
        if (!resources.length) {
            listEl.innerHTML = '<div class="info-text">暂无资源文件。可以点击"新建文件"或"自动获取"添加资源。</div>';
            return;
        }

        const grouped = {};
        resources.forEach(r => {
            const key = r.type === 'manual' ? 'manual' : `auto_${r.source || 'other'}`;
            if (!grouped[key]) grouped[key] = [];
            grouped[key].push(r);
        });

        let html = '';
        const groupLabels = {
            manual: '手动创建',
            auto_ipdeny: 'IPdeny (自动获取)',
            auto_shodan: 'Shodan (自动获取)',
            auto_fofa: 'FOFA (自动获取)',
            auto_other: '其他自动获取'
        };

        for (const [key, items] of Object.entries(grouped)) {
            html += `<div class="ip-resource-group"><div class="ip-resource-group-header">${groupLabels[key] || key}</div>`;
            items.forEach(item => {
                const tags = [];
                if (item.country_name) tags.push(`<span class="tag country">${item.country_name}</span>`);
                if (item.protocol_name) tags.push(`<span class="tag protocol">${item.protocol_name}</span>`);
                if (item.source_name) tags.push(`<span class="tag source">${item.source_name}</span>`);

                html += `
                <div class="ip-resource-item" data-path="${escapeHtml(item.path)}">
                    <div class="ip-resource-item-header">
                        <span class="ip-resource-item-name">${escapeHtml(item.filename)}</span>
                        <span class="ip-resource-item-count">${item.non_empty_lines} 行</span>
                    </div>
                    <div class="ip-resource-item-tags">${tags.join('')}</div>
                    <div class="ip-resource-item-meta">
                        ${item.fetch_time ? `<span>获取时间: ${formatDateTime(item.fetch_time)}</span>` : ''}
                        ${item.size_bytes ? `<span>大小: ${formatFileSize(item.size_bytes)}</span>` : ''}
                    </div>
                    <div class="ip-resource-item-actions">
                        <button type="button" class="btn btn-outline btn-sm ip-resource-edit-btn"><i class="fas fa-pen"></i>编辑</button>
                        ${item.type === 'manual' ? `<button type="button" class="btn btn-danger btn-sm ip-resource-delete-btn"><i class="fas fa-trash"></i>删除</button>` : ''}
                    </div>
                </div>`;
            });
            html += '</div>';
        }

        listEl.innerHTML = html;

        listEl.querySelectorAll('.ip-resource-edit-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const path = e.target.closest('.ip-resource-item').dataset.path;
                openEdit(path);
            });
        });

        listEl.querySelectorAll('.ip-resource-delete-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const path = e.target.closest('.ip-resource-item').dataset.path;
                deleteResource(path);
            });
        });
    }

    function updateFilterDropdowns(filters) {
        const sourceSelect = document.getElementById('ipResourceFilterSource');
        const currentValue = sourceSelect.value;
        sourceSelect.innerHTML = '<option value="">全部</option>';
        filters.sources.forEach(s => {
            sourceSelect.innerHTML += `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`;
        });
        sourceSelect.value = currentValue;

        const countrySelect = document.getElementById('ipResourceFilterCountry');
        const currentCountry = countrySelect.value;
        countrySelect.innerHTML = '<option value="">全部</option>';
        filters.countries.forEach(c => {
            countrySelect.innerHTML += `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`;
        });
        countrySelect.value = currentCountry;
    }

    async function openEdit(path) {
        try {
            const resource = await IPResourceManager.readResource(path);
            currentEditingResourcePath = path;

            document.getElementById('ipResourceEditFilename').value = resource.filename;
            document.getElementById('ipResourceEditContent').value = resource.content;
            document.getElementById('ipResourceEditPath').textContent = resource.path;
            document.getElementById('ipResourceEditSize').textContent = formatFileSize(resource.size_bytes);
            document.getElementById('ipResourceEditLines').textContent = resource.non_empty_lines;

            document.getElementById('ipResourceDeleteBtn').style.display = resource.type === 'manual' ? '' : 'none';
            document.getElementById('ipResourceModal').hidden = true;
            document.getElementById('ipResourceEditModal').hidden = false;
        } catch (e) {
            console.error('打开编辑失败:', e);
        }
    }

    async function saveEdit() {
        if (!currentEditingResourcePath) return;

        const content = document.getElementById('ipResourceEditContent').value;
        try {
            await IPResourceManager.writeResource(currentEditingResourcePath, content);
            closeEdit();
            loadResourceList();
        } catch (e) {
            console.error('保存失败:', e);
            alert('保存失败: ' + e.message);
        }
    }

    function closeEdit() {
        document.getElementById('ipResourceEditModal').hidden = true;
        currentEditingResourcePath = null;
    }

    async function deleteResource(path) {
        if (!confirm('确定要删除这个文件吗？')) return;

        try {
            await IPResourceManager.deleteResource(path);
            loadResourceList();
        } catch (e) {
            console.error('删除失败:', e);
            alert('删除失败: ' + e.message);
        }
    }

    function openNewModal() {
        document.getElementById('ipResourceNewFilename').value = '';
        document.getElementById('ipResourceNewContent').value = '';
        document.getElementById('ipResourceModal').hidden = true;
        document.getElementById('ipResourceNewModal').hidden = false;
    }

    async function createNew() {
        const filename = document.getElementById('ipResourceNewFilename').value.trim();
        const content = document.getElementById('ipResourceNewContent').value;

        if (!filename) {
            alert('请输入文件名');
            return;
        }

        try {
            await IPResourceManager.createResource(filename, content);
            closeNew();
            loadResourceList();
        } catch (e) {
            console.error('创建失败:', e);
            alert('创建失败: ' + e.message);
        }
    }

    function closeNew() {
        document.getElementById('ipResourceNewModal').hidden = true;
    }

    function openFetchModal() {
        document.getElementById('ipResourceFetchStatus').textContent = '';
        document.getElementById('ipResourceFetchParams').innerHTML = '';
        updateFetchParams();
        document.getElementById('ipResourceModal').hidden = true;
        document.getElementById('ipResourceFetchModal').hidden = false;
    }

    function updateFetchParams() {
        const source = document.getElementById('ipResourceFetchSource').value;
        const container = document.getElementById('ipResourceFetchParams');

        if (source === 'ipdeny') {
            container.innerHTML = `
                <div class="form-group">
                    <label>搜索国家</label>
                    <input type="text" id="ipResourceCountrySearch" placeholder="输入国家名称搜索..." class="wide">
                </div>
                <div class="form-group">
                    <label>选择国家（可多选）</label>
                    <div class="country-select-container">
                        <select id="ipResourceFetchCountries" multiple size="12" class="country-select">
                            ${ipResourceCountries.map(c => `<option value="${c.code}">${c.name} (${c.code.toUpperCase()})</option>`).join('')}
                        </select>
                    </div>
                    <div class="form-group" style="margin-top: 8px;">
                        <button type="button" id="ipResourceSelectAll" class="btn btn-outline btn-sm">全选</button>
                        <button type="button" id="ipResourceDeselectAll" class="btn btn-outline btn-sm">取消全选</button>
                    </div>
                    <div class="dns-field-hint">按住 Ctrl/Cmd 可多选，Shift 可选择范围</div>
                </div>`;

            const searchInput = document.getElementById('ipResourceCountrySearch');
            const selectEl = document.getElementById('ipResourceFetchCountries');
            const selectAllBtn = document.getElementById('ipResourceSelectAll');
            const deselectAllBtn = document.getElementById('ipResourceDeselectAll');

            searchInput?.addEventListener('input', (e) => {
                const keyword = e.target.value.toLowerCase();
                Array.from(selectEl.options).forEach(opt => {
                    const visible = opt.text.toLowerCase().includes(keyword);
                    opt.style.display = visible ? '' : 'none';
                });
            });

            selectAllBtn?.addEventListener('click', () => {
                Array.from(selectEl.options).forEach(opt => {
                    opt.selected = opt.style.display !== 'none';
                });
            });

            deselectAllBtn?.addEventListener('click', () => {
                Array.from(selectEl.options).forEach(opt => {
                    opt.selected = false;
                });
            });
        } else if (source === 'shodan' || source === 'fofa') {
            container.innerHTML = `
                <div class="form-group">
                    <label>选择协议类型</label>
                    <select id="ipResourceFetchProtocol">
                        <option value="dns">DNS</option>
                        <option value="memcached">Memcached</option>
                        <option value="ntp">NTP</option>
                        <option value="snmp">SNMP</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>结果数量限制</label>
                    <input type="number" id="ipResourceFetchLimit" value="1000" min="10" max="10000">
                </div>`;
        }
    }

    async function startFetch() {
        const source = document.getElementById('ipResourceFetchSource').value;
        const statusEl = document.getElementById('ipResourceFetchStatus');
        statusEl.textContent = '正在获取资源...';

        try {
            let params = {};
            if (source === 'ipdeny') {
                const countries = Array.from(document.getElementById('ipResourceFetchCountries').selectedOptions)
                    .map(opt => opt.value);
                params = { countries };
            } else if (source === 'shodan' || source === 'fofa') {
                const protocol = document.getElementById('ipResourceFetchProtocol').value;
                const limit = parseInt(document.getElementById('ipResourceFetchLimit').value);
                params = { queries: [protocol], limit };
            }

            const result = await IPResourceManager.fetchAutoResources(source, params);

            if (result.success) {
                const files = result.files || [];
                const successCount = files.filter(f => !f.error).length;
                statusEl.innerHTML = `<span style="color:green;">获取完成！成功 ${successCount}/${files.length} 个资源</span>`;
                setTimeout(() => {
                    closeFetch();
                    loadResourceList();
                }, 1500);
            } else {
                statusEl.innerHTML = `<span style="color:red;">获取失败: ${result.error || '未知错误'}</span>`;
            }
        } catch (e) {
            statusEl.innerHTML = `<span style="color:red;">获取失败: ${e.message}</span>`;
        }
    }

    function closeFetch() {
        document.getElementById('ipResourceFetchModal').hidden = true;
    }

    function escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function formatDateTime(isoStr) {
        try {
            const date = new Date(isoStr);
            return date.toLocaleString('zh-CN');
        } catch {
            return isoStr;
        }
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    return {
        openManageModal,
        closeManageModal,
        loadResourceList,
        openEdit,
        saveEdit,
        closeEdit,
        deleteResource,
        openNewModal,
        createNew,
        closeNew,
        openFetchModal,
        updateFetchParams,
        startFetch,
        closeFetch
    };
})();

const FormPersistence = (() => {
    const NS = "pressure_console:";
    const VERSION = 1;

    function getStorage(type) {
        try {
            return type === "session" ? sessionStorage : localStorage;
        } catch (e) {
            return null;
        }
    }

    function save(key, data, type = "session") {
        const storage = getStorage(type);
        if (!storage) return false;
        try {
            const payload = { v: VERSION, ts: Date.now(), data };
            storage.setItem(NS + key, JSON.stringify(payload));
            return true;
        } catch (e) {
            console.warn("FormPersistence save failed:", e);
            return false;
        }
    }

    function load(key, type = "session") {
        const storage = getStorage(type);
        if (!storage) return null;
        try {
            const raw = storage.getItem(NS + key);
            if (!raw) return null;
            const payload = JSON.parse(raw);
            if (payload.v !== VERSION) return null;
            return payload.data;
        } catch (e) {
            console.warn("FormPersistence load failed:", e);
            return null;
        }
    }

    function clear(key, type = "session") {
        const storage = getStorage(type);
        if (!storage) return;
        try {
            storage.removeItem(NS + key);
        } catch (e) {
            console.warn("FormPersistence clear failed:", e);
        }
    }

    function readFormFields(formSelector, fieldMap) {
        const result = {};
        const form = document.querySelector(formSelector);
        if (!form) return result;
        for (const [key, selector] of Object.entries(fieldMap)) {
            const el = form.querySelector(selector);
            if (!el) continue;
            if (el.type === "checkbox") {
                result[key] = el.checked;
            } else if (el.type === "radio") {
                const checked = form.querySelector(`${selector}:checked`);
                result[key] = checked ? checked.value : "";
            } else {
                result[key] = el.value;
            }
        }
        return result;
    }

    function writeFormFields(formSelector, fieldMap, data) {
        if (!data) return false;
        const form = document.querySelector(formSelector);
        if (!form) return false;
        let applied = false;
        for (const [key, selector] of Object.entries(fieldMap)) {
            if (!(key in data)) continue;
            const el = form.querySelector(selector);
            if (!el) continue;
            if (el.type === "checkbox") {
                el.checked = Boolean(data[key]);
            } else if (el.type === "radio") {
                const radio = form.querySelector(`${selector}[value="${CSS.escape(data[key])}"]`);
                if (radio) radio.checked = true;
            } else {
                el.value = data[key];
            }
            el.dispatchEvent(new Event("change", { bubbles: true }));
            el.dispatchEvent(new Event("input", { bubbles: true }));
            applied = true;
        }
        return applied;
    }

    function readCheckboxGroup(containerSelector, checkboxSelector = 'input[type="checkbox"]') {
        const container = document.querySelector(containerSelector);
        if (!container) return [];
        return Array.from(container.querySelectorAll(`${checkboxSelector}:checked`)).map((cb) => cb.value);
    }

    function writeCheckboxGroup(containerSelector, values, checkboxSelector = 'input[type="checkbox"]') {
        const container = document.querySelector(containerSelector);
        if (!container || !Array.isArray(values)) return;
        const valueSet = new Set(values);
        container.querySelectorAll(checkboxSelector).forEach((cb) => {
            cb.checked = valueSet.has(cb.value);
        });
    }

    return { save, load, clear, readFormFields, writeFormFields, readCheckboxGroup, writeCheckboxGroup };
})();

const CONSOLE_FIELD_MAP = {
    target_ip: "#target_ip",
    target_port: "#target_port",
    duration: "#duration",
    threads: "#threads",
    target_pps: "#target_pps",
    multi_protocol: "#multi_protocol",
    method: "#method"
};

const ATTACK_RESOURCE_FIELD_MAPS = {
    tcp: {
        ip_file: "#tcpIpFile",
        target_host: "#tcpTargetHost",
        pkt_method: "#tcpPktMethod",
        scan_rate: "#tcpScanRate",
        ttl: "#tcpTtl",
        scan_count: "#tcpScanCount",
        result_limit: "#tcpResultLimit",
        length_threshold: "#tcpLengthThreshold",
        min_amplification: "#tcpMinAmplification",
        min_success_rate: "#tcpMinSuccessRate",
        network_interface: "#tcpNetworkInterface",
        dry_run: "#tcpDryRun"
    },
    dns: {
        ip_file: "#dnsIpFile",
        test_domains: "#dnsTestDomains",
        query_type: "#dnsQueryType",
        use_dnssec: "#dnsUseDnssec",
        concurrency: "#dnsConcurrency",
        timeout_sec: "#dnsTimeout",
        min_amplification: "#dnsMinAmplification",
        min_reliability: "#dnsMinReliability"
    },
    ntp: {
        ip_file: "#ntpIpFile",
        probe_action: "#ntpProbeAction",
        concurrency: "#ntpConcurrency",
        timeout_sec: "#ntpTimeout",
        min_amplification: "#ntpMinAmplification",
        min_availability: "#ntpMinAvailability"
    },
    memcached: {
        ip_file: "#memcachedIpFile",
        cmd_type: "#memcachedCmdType",
        data_size_kb: "#memcachedDataSizeKb",
        concurrency: "#memcachedConcurrency",
        timeout_sec: "#memcachedTimeout",
        min_amplification: "#memcachedMinAmplification",
        min_reliability: "#memcachedMinReliability"
    }
};

const LATENCY_FIELD_MAP = {
    target_ip: "#latencyTargetIp",
    port: "#latencyPort"
};

// 输出文件作用描述字典
// TCP 文件名含动态 stem 和 pkt_method，用前缀/后缀模式匹配
// DNS/NTP/Memcached 文件名固定，用精确匹配
const OUTPUT_FILE_DESCRIPTIONS = {
    // === TCP 12 个文件 ===
    // 精确匹配
    "qualified_ips.txt": "优质反射器 IP 列表（放大率与成功率均达标），每行一个纯 IP，可直接用于攻击",
    "extract_qualified_ips.log": "优质 IP 提取阶段的日志，记录筛选阈值与入选/淘汰情况",
    "process_csv.log": "CSV 处理阶段日志，记录从 ZMap 原始结果清洗 IP 的过程",
    "extract_ips.log": "IP 提取阶段日志，记录从处理后的 CSV 提取 IP 列表的过程",
    "analysis_stdout_stderr.log": "放大分析脚本（analyze_amplify_log.py）的 stdout/stderr 输出",
    // 后缀匹配（key 以 * 开头表示后缀匹配）
    "*_processed.csv": "处理后的扫描结果 CSV，清洗并格式化 ZMap 原始输出",
    "*-IPs.txt": "从扫描结果提取的候选 IP 列表，用于后续放大测试",
    "*_zmap_scan_details.log": "ZMap 扫描过程详细日志，记录发包与响应统计",
    // 前缀匹配（key 以 * 结尾表示前缀匹配）
    "amplification_test_*.log": "放大测试阶段日志，记录每个 IP 每次扫描的发送/接收字节数与放大比率",
    "magnification_test_stdout_stderr_*.log": "放大测试子进程（magnification_test.py）的 stdout/stderr 输出",
    "amplification_analysis_report_*.txt": "放大分析报告，含 IP 综合得分、放大率、稳定性、成功率排名",
};

// DNS/NTP/Memcached 共用的 3 个固定文件（文件名相同，描述按协议微调）
const PROTOCOL_FILE_DESCRIPTIONS = {
    dns: {
        "qualified_ips.txt": "DNS 优质反射器 IP 列表（放大率 ≥ 阈值），每行一个纯 IP",
        "scan_results.csv": "完整扫描结果 CSV，含 IP、域名、查询类型、响应字节数、放大率、延迟、错误等",
        "scan_summary.json": "JSON 汇总，含总 IP 数、响应数、优质数、平均/最大放大率、Top10 排名",
    },
    ntp: {
        "qualified_ips.txt": "NTP 优质反射器 IP 列表（放大率 ≥ 阈值），每行一个纯 IP",
        "scan_results.csv": "完整扫描结果 CSV，含 IP、动作、响应字节数、放大率、响应包数、延迟、错误等",
        "scan_summary.json": "JSON 汇总，含总 IP 数、响应数、优质数、平均/最大放大率、Top10 排名",
    },
    memcached: {
        "qualified_ips.txt": "Memcached 优质反射器 IP 列表（放大率 ≥ 阈值），每行一个纯 IP",
        "scan_results.csv": "完整扫描结果 CSV，含 IP、命令类型、可用性、响应字节数、放大率、数据大小、延迟等",
        "scan_summary.json": "JSON 汇总，含总 IP 数、响应数、优质数、平均/最大放大率、Top10 排名",
    },
};

// 按文件名和协议获取描述
function getFileDescription(fileName, protocol) {
    // 1. 先查协议专属字典（DNS/NTP/Memcached 精确匹配）
    if (protocol && PROTOCOL_FILE_DESCRIPTIONS[protocol]) {
        const desc = PROTOCOL_FILE_DESCRIPTIONS[protocol][fileName];
        if (desc) return desc;
    }
    // 2. 再查通用字典（TCP 精确 + 前缀/后缀）
    if (OUTPUT_FILE_DESCRIPTIONS[fileName]) {
        return OUTPUT_FILE_DESCRIPTIONS[fileName];
    }
    // 3. 后缀匹配（key 以 * 开头）
    for (const key of Object.keys(OUTPUT_FILE_DESCRIPTIONS)) {
        if (key.startsWith("*") && !key.endsWith("*")) {
            const suffix = key.slice(1);
            if (fileName.endsWith(suffix) && OUTPUT_FILE_DESCRIPTIONS[key]) {
                return OUTPUT_FILE_DESCRIPTIONS[key];
            }
        }
    }
    // 4. 前缀匹配（key 以 * 结尾）
    for (const key of Object.keys(OUTPUT_FILE_DESCRIPTIONS)) {
        if (key.endsWith("*") && !key.startsWith("*")) {
            const prefix = key.slice(0, -1);
            if (fileName.startsWith(prefix) && OUTPUT_FILE_DESCRIPTIONS[key]) {
                return OUTPUT_FILE_DESCRIPTIONS[key];
            }
        }
    }
    // 4.5 中间 * 匹配（如 amplification_test_*.log，按 * 拆成 prefix+suffix）
    for (const key of Object.keys(OUTPUT_FILE_DESCRIPTIONS)) {
        const starIdx = key.indexOf("*");
        if (starIdx > 0 && starIdx < key.length - 1) {
            const prefix = key.slice(0, starIdx);
            const suffix = key.slice(starIdx + 1);
            if (fileName.startsWith(prefix) && fileName.endsWith(suffix) && OUTPUT_FILE_DESCRIPTIONS[key]) {
                return OUTPUT_FILE_DESCRIPTIONS[key];
            }
        }
    }
    // 5. TCP 的 raw_csv 兜底：*.csv 但不是 _processed.csv
    if (protocol === "tcp" && fileName.endsWith(".csv") && !fileName.endsWith("_processed.csv")) {
        return "ZMap 原始扫描结果 CSV，包含响应 IP 及其元数据";
    }
    return "";
}

function saveUiState() {
    const state = {
        currentView: currentView,
        currentAttackResourceProto: currentAttackResourceProto,
        lastVisitedWorkflowStep: lastVisitedWorkflowStep
    };
    const collapsibleSections = [];
    document.querySelectorAll(".collapsible-section.open").forEach((section, idx) => {
        const trigger = section.querySelector(".collapsible-trigger span");
        if (trigger) collapsibleSections.push(trigger.textContent.trim() || idx);
    });
    if (collapsibleSections.length) state.openCollapsibles = collapsibleSections;
    FormPersistence.save("session:ui_state", state, "session");
}

function restoreUiState() {
    const state = FormPersistence.load("session:ui_state", "session");
    if (!state) return false;
    if (state.currentView && document.getElementById(`view-${state.currentView}`)) {
        currentView = state.currentView;
    }
    if (state.currentAttackResourceProto) {
        currentAttackResourceProto = state.currentAttackResourceProto;
    }
    if (state.lastVisitedWorkflowStep) {
        lastVisitedWorkflowStep = state.lastVisitedWorkflowStep;
    }
    if (Array.isArray(state.openCollapsibles) && state.openCollapsibles.length) {
        document.querySelectorAll(".collapsible-section").forEach((section) => {
            const trigger = section.querySelector(".collapsible-trigger span");
            const label = trigger ? trigger.textContent.trim() : "";
            if (state.openCollapsibles.includes(label)) {
                section.classList.add("open");
                const trig = section.querySelector(".collapsible-trigger");
                if (trig) trig.setAttribute("aria-expanded", "true");
            }
        });
    }
    return true;
}

function initUiStatePersistence() {
    const state = FormPersistence.load("session:ui_state", "session");
    if (state) {
        if (state.currentAttackResourceProto) {
            currentAttackResourceProto = state.currentAttackResourceProto;
        }
        if (state.lastVisitedWorkflowStep) {
            lastVisitedWorkflowStep = state.lastVisitedWorkflowStep;
        }
        if (Array.isArray(state.openCollapsibles) && state.openCollapsibles.length) {
            document.querySelectorAll(".collapsible-section").forEach((section) => {
                const trigger = section.querySelector(".collapsible-trigger span");
                const label = trigger ? trigger.textContent.trim() : "";
                if (state.openCollapsibles.includes(label)) {
                    section.classList.add("open");
                    const trig = section.querySelector(".collapsible-trigger");
                    if (trig) trig.setAttribute("aria-expanded", "true");
                }
            });
        }
    }

    const origNavigateToView = window.navigateToView;
    if (typeof origNavigateToView === "function") {
        window.navigateToView = function(view) {
            const result = origNavigateToView.apply(this, arguments);
            saveUiState();
            return result;
        };
    }

    const origSwitchAttackResourceProto = window.switchAttackResourceProto;
    if (typeof origSwitchAttackResourceProto === "function") {
        window.switchAttackResourceProto = function(proto) {
            const result = origSwitchAttackResourceProto.apply(this, arguments);
            saveUiState();
            return result;
        };
    }

    document.addEventListener("click", (e) => {
        const trigger = e.target.closest(".collapsible-trigger");
        if (trigger) {
            setTimeout(saveUiState, 0);
        }
    });

    if (state && state.currentView && document.getElementById(`view-${state.currentView}`)) {
        setTimeout(() => navigateToView(state.currentView), 0);
    }
}

const WORKFLOW_STEP_ORDER = ["pool", "resource", "console", "latency"];
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
    initUiStatePersistence();
    initProtocolCheckboxes();
    initProtoSourceButtons();
    bindControls();
    initAttackResourceView();
    initAttackResourceTaskFramework();
    initIpResourceManager();
    FileSystemUi.init();
    toggleMultiProtocol();
    initConsoleFormPersistence();
    initLatencyFormPersistence();
    loadAllServerCounts();
    loadServerGeoMap();
    pollStatus();
    bindWorkflowActions();
    updateWorkflowIndicators();
    updateSystemInfo();
    updateDetailedSystemInfo();
    setInterval(updateSystemInfo, 3000);
    setInterval(updateDetailedSystemInfo, 2000);
});

function initIpResourceManager() {
    IPResourceManager.fetchCountries().catch(() => {});
    IPResourceManager.fetchSources().catch(() => {});

    document.getElementById('attackResourceManageBtn')?.addEventListener('click', IPResourceUi.openManageModal);
    document.getElementById('ipResourceModalClose')?.addEventListener('click', IPResourceUi.closeManageModal);
    document.getElementById('ipResourceRefreshBtn')?.addEventListener('click', IPResourceUi.loadResourceList);
    document.getElementById('ipResourceNewBtn')?.addEventListener('click', IPResourceUi.openNewModal);
    document.getElementById('ipResourceFetchBtn')?.addEventListener('click', IPResourceUi.openFetchModal);

    document.getElementById('ipResourceFilterType')?.addEventListener('change', IPResourceUi.loadResourceList);
    document.getElementById('ipResourceFilterSource')?.addEventListener('change', IPResourceUi.loadResourceList);
    document.getElementById('ipResourceFilterCountry')?.addEventListener('change', IPResourceUi.loadResourceList);
    document.getElementById('ipResourceFilterProtocol')?.addEventListener('change', IPResourceUi.loadResourceList);

    document.getElementById('ipResourceEditClose')?.addEventListener('click', IPResourceUi.closeEdit);
    document.getElementById('ipResourceEditCancel')?.addEventListener('click', IPResourceUi.closeEdit);
    document.getElementById('ipResourceEditSave')?.addEventListener('click', IPResourceUi.saveEdit);
    document.getElementById('ipResourceDeleteBtn')?.addEventListener('click', () => {
        if (currentEditingResourcePath) {
            IPResourceUi.deleteResource(currentEditingResourcePath);
        }
    });

    document.getElementById('ipResourceNewClose')?.addEventListener('click', IPResourceUi.closeNew);
    document.getElementById('ipResourceNewCancel')?.addEventListener('click', IPResourceUi.closeNew);
    document.getElementById('ipResourceNewCreate')?.addEventListener('click', IPResourceUi.createNew);

    document.getElementById('ipResourceFetchClose')?.addEventListener('click', IPResourceUi.closeFetch);
    document.getElementById('ipResourceFetchCancel')?.addEventListener('click', IPResourceUi.closeFetch);
    document.getElementById('ipResourceFetchStart')?.addEventListener('click', IPResourceUi.startFetch);
    document.getElementById('ipResourceFetchSource')?.addEventListener('change', IPResourceUi.updateFetchParams);

    document.querySelectorAll('[data-dismiss="ip-resource-modal"]').forEach(el => {
        el.addEventListener('click', IPResourceUi.closeManageModal);
    });
    document.querySelectorAll('[data-dismiss="ip-resource-edit-modal"]').forEach(el => {
        el.addEventListener('click', IPResourceUi.closeEdit);
    });
    document.querySelectorAll('[data-dismiss="ip-resource-fetch-modal"]').forEach(el => {
        el.addEventListener('click', IPResourceUi.closeFetch);
    });
    document.querySelectorAll('[data-dismiss="ip-resource-new-modal"]').forEach(el => {
        el.addEventListener('click', IPResourceUi.closeNew);
    });
}

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
    if (proto === "memcached") {
        attackResourceControllers["memcached"]?.refresh?.();
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
    document.getElementById("singleProtoSourceBtn")?.addEventListener("click", openSingleProtoSourceModal);
    document.getElementById("singleProtoViewEditBtn")?.addEventListener("click", openSingleProtoViewEditModal);
    document.getElementById("clearServerSelectionBtn")?.addEventListener("click", clearServerSelection);
    document.querySelectorAll(".map-view-btn").forEach((btn) => {
        btn.addEventListener("click", () => switchServerMapMode(btn.dataset.mapView || "3d"));
    });
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

function setServerSourceApplyHandler(handler) {
    const applyBtn = document.getElementById("serverSourceApplyBtn");
    if (!applyBtn) return;
    applyBtn.onclick = handler;
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
    if (view === "file-management") {
        FileSystemUi.load();
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

function getServerSourceIdentifier(item) {
    return item?.id || item?.path || item?.name || "";
}

function getServerSourceLabel(item) {
    if (!item) return "";
    return item.display_name || item.name || item.filename || getServerSourceIdentifier(item);
}

function getServerSourceMap(proto = currentProto) {
    const map = new Map();
    getAvailableServerSources(proto).forEach((item) => {
        const key = getServerSourceIdentifier(item);
        if (key) map.set(key, item);
        if (item?.name) map.set(item.name, item);
        if (item?.path) map.set(item.path, item);
    });
    return map;
}

function resolveServerSourceItem(proto = currentProto, identifier = "") {
    return getServerSourceMap(proto).get(identifier) || null;
}

function getDefaultServerSources(proto, sources) {
    if (!sources.length) return [];
    return sources.map((item) => getServerSourceIdentifier(item)).filter(Boolean);
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
    const validNames = new Set(sources.map((item) => getServerSourceIdentifier(item)));
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
    if (selected.length === 1) return getServerSourceLabel(resolveServerSourceItem(proto, selected[0])) || selected[0];
    return `${selected.length} 个源文件`;
}

function getMultiProtoSelectedSources(proto) {
    return multiProtoSelectedSources[proto] || [];
}

async function ensureMultiProtoSourceSelection(proto) {
    const sources = await fetchServerSourceFiles(proto, true);
    const selected = getMultiProtoSelectedSources(proto);
    const validNames = new Set(sources.map((item) => getServerSourceIdentifier(item)));
    const filtered = selected.filter((name) => validNames.has(name));
    const nextSelection = filtered.length ? filtered : getDefaultServerSources(proto, sources);
    multiProtoSelectedSources[proto] = nextSelection;
    return nextSelection;
}

function updateProtoSourceButtonLabel(proto) {
    const btn = document.querySelector(`.proto-source-btn[data-proto="${proto}"]`);
    const label = btn?.querySelector(".proto-source-label");
    if (!label) return;
    const selected = getMultiProtoSelectedSources(proto);
    if (!selected.length) {
        label.textContent = "全部文件";
    } else if (selected.length === 1) {
        label.textContent = getServerSourceLabel(resolveServerSourceItem(proto, selected[0])) || selected[0];
    } else {
        label.textContent = `${selected.length} 个文件`;
    }
}

async function applyMultiProtoSourceSelection(proto) {
    const body = document.getElementById("serverSourceModalBody");
    const selected = Array.from(body?.querySelectorAll("input[type='checkbox']:checked") || [])
        .map((input) => input.value)
        .filter(Boolean);
    if (!selected.length) {
        showNotification("请至少选择一个源文件", "error");
        return;
    }
    multiProtoSelectedSources[proto] = selected;
    closeServerSourceModal();
    updateProtoSourceButtonLabel(proto);
    saveConsoleFormSession();
    // 刷新资源计数
    loadReflectorCount(selectedProtocols.length ? selectedProtocols : [proto]);
}

async function openMultiProtoSourcePicker(proto) {
    try {
        serverSourceModalProto = proto;
        await ensureMultiProtoSourceSelection(proto);
        // 临时设置 currentProto 以复用现有 Modal
        const savedProto = currentProto;
        currentProto = proto;
        await ensureServerSourceSelection(proto, true);
        // 渲染 Modal 时使用 multiProtoSelectedSources
        renderMultiProtoSourceModal(proto);
        const modal = document.getElementById("serverSourceModal");
        if (modal) modal.hidden = false;
        setServerSourceApplyHandler(applyServerSourceSelection);
        // 保存 proto 用于 apply 时使用
        currentProto = savedProto;
        setServerSourceApplyHandler(() => applyMultiProtoSourceSelection(proto));
    } catch (error) {
        showNotification(`加载源文件失败：${error.message}`, "error");
    }
}

function renderMultiProtoSourceModal(proto) {
    const title = document.getElementById("serverSourceModalTitle");
    const body = document.getElementById("serverSourceModalBody");
    const sources = getAvailableServerSources(proto);
    const selected = new Set(getMultiProtoSelectedSources(proto));
    if (title) title.textContent = `${getMethodText(proto)} 源文件选择`;
    if (!body) return;
    if (!sources.length) {
        body.innerHTML = `<div class="server-source-summary">当前协议没有可用源文件。</div>`;
        return;
    }
    body.innerHTML = `
        <div class="server-source-summary">
            当前协议：${escapeHtml(getMethodText(proto))}。选中的文件会按并集合并使用。
        </div>
        <div class="server-source-list">
            ${sources.map((file) => `
                <label class="server-source-item">
                    <input type="checkbox" value="${escapeHtml(getServerSourceIdentifier(file))}" ${selected.has(getServerSourceIdentifier(file)) ? "checked" : ""}>
                    <span>
                        <strong>${escapeHtml(getServerSourceLabel(file))}</strong>
                        <span>${escapeHtml(file.path || "")}</span>
                    </span>
                    <em>${escapeHtml(String(file.entry_count || 0))} 条</em>
                </label>
            `).join("")}
        </div>
    `;
}

async function initProtoSourceButtons() {
    document.querySelectorAll(".proto-source-btn[data-proto]").forEach((btn) => {
        btn.addEventListener("click", async (e) => {
            e.preventDefault();
            e.stopPropagation();
            const proto = btn.dataset.proto;
            await openMultiProtoSourcePicker(proto);
        });
    });
    // 初始化每个协议的默认选择
    for (const btn of document.querySelectorAll(".proto-source-btn[data-proto]")) {
        const proto = btn.dataset.proto;
        try {
            await ensureMultiProtoSourceSelection(proto);
            updateProtoSourceButtonLabel(proto);
        } catch (e) {
            // 连接失败时静默
        }
    }
}

// ======= 单协议源文件选择 =======

function updateSingleSourceLabel() {
    const label = document.getElementById("singleProtoSourceLabel");
    if (!label) return;
    if (!singleSelectedSources.length) {
        label.textContent = "全部文件";
    } else if (singleSelectedSources.length === 1) {
        label.textContent = singleSelectedSources[0];
    } else {
        label.textContent = `${singleSelectedSources.length} 个源文件`;
    }
}

async function openSingleProtoSourceModal() {
    const method = document.getElementById("method")?.value;
    if (!method) {
        showNotification("请先选择测试协议", "error");
        return;
    }
    serverSourceModalProto = method;
    try {
        await ensureServerSourceSelection(method, true);
        renderSingleProtoSourceModal(method);
        const modal = document.getElementById("serverSourceModal");
        if (modal) modal.hidden = false;
        setServerSourceApplyHandler(() => applySingleProtoSourceSelection(method));
    } catch (error) {
        showNotification(`源文件加载失败：${error.message}`, "error");
    }
}

function renderSingleProtoSourceModal(proto) {
    const title = document.getElementById("serverSourceModalTitle");
    const body = document.getElementById("serverSourceModalBody");
    const sources = getAvailableServerSources(proto);
    const selected = new Set(singleSelectedSources.length ? singleSelectedSources : getAllSourceNames(sources));
    if (title) title.textContent = `${getMethodText(proto)} 源文件选择`;
    if (!body) return;
    if (!sources.length) {
        body.innerHTML = `<div class="server-source-summary">当前协议没有可用源文件。</div>`;
        return;
    }
    body.innerHTML = `
        <div class="server-source-summary">
            当前协议：${escapeHtml(getMethodText(proto))}。选中的文件会用于单协议测试。
        </div>
        <div class="server-source-list">
            ${sources.map((file) => `
                <label class="server-source-item">
                    <input type="checkbox" value="${escapeHtml(getServerSourceIdentifier(file))}" ${selected.has(getServerSourceIdentifier(file)) ? "checked" : ""}>
                    <span>
                        <strong>${escapeHtml(getServerSourceLabel(file))}</strong>
                        <span>${escapeHtml(file.path || "")}</span>
                    </span>
                    <em>${escapeHtml(String(file.entry_count || 0))} 条</em>
                </label>
            `).join("")}
        </div>
    `;
}

function getAllSourceNames(sources) {
    return sources.map((s) => s.name);
}

function applySingleProtoSourceSelection(proto) {
    const body = document.getElementById("serverSourceModalBody");
    const selected = Array.from(body?.querySelectorAll("input[type='checkbox']:checked") || [])
        .map((input) => input.value)
        .filter(Boolean);
    if (!selected.length) {
        showNotification("请至少选择一个源文件", "error");
        return;
    }
    singleSelectedSources = selected;
    closeServerSourceModal();
    updateSingleSourceLabel();
    saveConsoleFormSession();
    showNotification(`已选择 ${selected.length} 个源文件`, "success");
}

async function openSingleProtoViewEditModal() {
    const method = document.getElementById("method")?.value;
    if (!method) {
        showNotification("请先选择测试协议", "error");
        return;
    }
    // 如果没有选择源文件，先用协议的默认文件
    if (!singleSelectedSources.length) {
        try {
            await ensureServerSourceSelection(method, true);
            const sources = getAvailableServerSources(method);
            if (sources.length) {
                singleSelectedSources = [sources[0].name];
                updateSingleSourceLabel();
            }
        } catch (error) {
            showNotification(`源文件加载失败：${error.message}`, "error");
            return;
        }
    }
    // 使用 openServerEditorModal 打开编辑，它会自动设置 currentProto/currentServerSource
    const fileToEdit = singleSelectedSources[0];
    if (!fileToEdit) {
        showNotification("未找到可编辑的源文件", "error");
        return;
    }
    // 临时同步 selectedServerSourcesByProto 以复用在资源池中的编辑器
    const savedProto = currentProto;
    currentProto = method;
    selectedServerSourcesByProto[method] = singleSelectedSources;
    try {
        await openServerEditorModal(fileToEdit, method);
    } finally {
        currentProto = savedProto;
    }
}

function bindTcpModalControls() {
    document.getElementById("tcpStopCleanupBtn")?.addEventListener("click", () => stopTcpScan(true));
    document.getElementById("tcpFileModalClose")?.addEventListener("click", closeTcpFileModal);
    document.querySelector('[data-dismiss="tcp-file-modal"]')?.addEventListener("click", closeTcpFileModal);
    document.getElementById("tcpFileSaveBtn")?.addEventListener("click", saveTcpFileContent);
    document.getElementById("tcpFileReloadBtn")?.addEventListener("click", reloadTcpFileContent);
    document.getElementById("serverSourceModalClose")?.addEventListener("click", closeServerSourceModal);
    document.querySelector('[data-dismiss="server-source-modal"]')?.addEventListener("click", closeServerSourceModal);
    setServerSourceApplyHandler(applyServerSourceSelection);
    document.getElementById("serverSourceNewFileBtn")?.addEventListener("click", openServerSourceNewFileDialog);
    document.getElementById("serverFileModalClose")?.addEventListener("click", closeServerFileModal);
    document.querySelector('[data-dismiss="server-file-modal"]')?.addEventListener("click", closeServerFileModal);
    document.getElementById("serverFileSaveBtn")?.addEventListener("click", saveServerFileContent);
    document.getElementById("serverFileReloadBtn")?.addEventListener("click", reloadServerFileContent);
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
        ["最小放大率", summary.config?.min_amplification ?? "-"],
        ["最小成功率", summary.config?.min_success_rate ?? "-"],
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
    container.innerHTML = files.map((file) => {
        const desc = getFileDescription(file.name, "tcp");
        const infoIcon = desc
            ? `<span class="file-info-icon" data-tooltip="${escapeHtml(desc)}" title="">ℹ️</span>`
            : "";
        return `<button type="button" class="tcp-artifact-item tcp-file-button" data-file-name="${escapeHtml(file.name)}">
            <span>${escapeHtml(file.name)}</span>${infoIcon}
            <strong>${formatBytes(file.bytes || 0)}</strong>
        </button>`;
    }).join("");
    container.querySelectorAll("[data-file-name]").forEach((item) => {
        item.addEventListener("click", () => openTcpFileModal(item.getAttribute("data-file-name")));
    });
    container.querySelectorAll(".file-info-icon").forEach((icon) => {
        icon.addEventListener("click", (e) => e.stopPropagation());
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

function buildGeoPointsFromPool(ips, areas) {
    const areaByIp = new Map();
    (Array.isArray(areas) ? areas : []).forEach((area) => {
        (Array.isArray(area.ips) ? area.ips : []).forEach((ip) => {
            if (!areaByIp.has(ip)) areaByIp.set(ip, area);
        });
    });
    return (Array.isArray(ips) ? ips : []).map((ip) => {
        const area = areaByIp.get(ip) || {};
        return {
            ip,
            entries: [ip],
            country: area.country || "",
            country_code: area.country_code || "",
            region: area.region || "",
            region_code: area.region_code || "",
            city: "",
            isp: "",
            lat: undefined,
            lon: undefined,
            stale: false
        };
    });
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
            const firstAreaPoint = lastGeoPoints.find((point) => area.ips.includes(point.ip)
                && Number.isFinite(Number(point.lat)) && Number.isFinite(Number(point.lon)));
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
        const emptyText = serverUnresolvedCount > 0
            ? `另有 ${serverUnresolvedCount} 个未定位 IP（质量 IP 池仅提供数量统计）。`
            : "当前没有未定位条目。";
        container.innerHTML = `<div class="info-text">${emptyText}</div>`;
        return;
    }
    container.innerHTML = serverUnresolvedItems.map((item) => `
        <div class="server-unresolved-item">
            <strong>${escapeHtml(item.entry)}</strong>
            <span>${escapeHtml(formatGeoReason(item.reason))}</span>
        </div>
    `).join("");
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
                    <input type="checkbox" value="${escapeHtml(getServerSourceIdentifier(file))}" ${selected.has(getServerSourceIdentifier(file)) ? "checked" : ""}>
                    <span>
                        <strong>${escapeHtml(getServerSourceLabel(file))}</strong>
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
        serverSourceModalProto = currentProto;
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

async function openServerSourceNewFileDialog() {
    const proto = serverSourceModalProto;
    if (!proto) {
        showNotification("未知协议", "error");
        return;
    }
    const name = prompt("请输入新文件名（.txt 后缀可选）：", `${proto}_new.txt`);
    if (!name || !name.trim()) return; // 用户取消
    try {
        const response = await fetch(`/api/servers/${proto}/file`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ filename: name.trim() })
        });
        const data = await response.json();
        if (!data.success) {
            showNotification(data.message || "创建文件失败", "error");
            return;
        }
        showNotification(data.message || "文件已创建", "success");
        // 刷新协议源文件列表缓存
        await ensureServerSourceSelection(proto, true);
        // 重新渲染当前 Modal，新文件默认选中
        const body = document.getElementById("serverSourceModalBody");
        const sources = getAvailableServerSources(proto);
        const newFileName = data.file.id || data.file.path || data.file.name;
        const existingChecked = Array.from(body?.querySelectorAll("input[type='checkbox']:checked") || [])
            .map((cb) => cb.value);
        const newSelection = new Set([...existingChecked, newFileName]);
        if (!body) return;
        if (!sources.length) {
            body.innerHTML = `<div class="server-source-summary">当前协议没有可用源文件。</div>`;
            return;
        }
        body.innerHTML = `
            <div class="server-source-summary">
                当前协议：${escapeHtml(getMethodText(proto))}。选中的文件会按并集合并使用。
            </div>
            <div class="server-source-list">
                ${sources.map((file) => `
                    <label class="server-source-item">
                        <input type="checkbox" value="${escapeHtml(getServerSourceIdentifier(file))}" ${newSelection.has(getServerSourceIdentifier(file)) ? "checked" : ""}>
                        <span>
                            <strong>${escapeHtml(getServerSourceLabel(file))}</strong>
                            <span>${escapeHtml(file.path || "")}</span>
                        </span>
                        <em>${escapeHtml(String(file.entry_count || 0))} 条</em>
                    </label>
                `).join("")}
            </div>
        `;
    } catch (error) {
        showNotification(`创建文件失败：${error.message}`, "error");
    }
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
    await openServerEditorModal(selected[0], currentProto);
}

function renderServerFileModal(file) {
    const title = document.getElementById("serverFileModalTitle");
    const body = document.getElementById("serverFileModalBody");
    const saveBtn = document.getElementById("serverFileSaveBtn");
    const reloadBtn = document.getElementById("serverFileReloadBtn");
    const selected = getSelectedServerSources(currentServerEditorProto);
    if (title) title.textContent = file.name || "编辑源文件";
    if (saveBtn) saveBtn.disabled = !file.editable;
    if (reloadBtn) reloadBtn.disabled = false;
    if (!body) return;

    const switcher = selected.length > 1 ? `
        <div class="server-file-switcher">
            <label for="serverFileSourceSelect">当前编辑文件</label>
            <select id="serverFileSourceSelect">
                ${selected.map((source) => `<option value="${escapeHtml(source)}" ${source === currentServerSource ? "selected" : ""}>${escapeHtml(getServerSourceLabel(resolveServerSourceItem(currentServerEditorProto, source)) || source)}</option>`).join("")}
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
        await openServerEditorModal(event.target.value, currentServerEditorProto);
    });
}

async function openServerEditorModal(sourceName = "", proto = currentServerEditorProto || currentProto) {
    try {
        const selected = getSelectedServerSources(proto);
        const nextSource = sourceName || currentServerSource || selected[0] || "";
        if (!nextSource) throw new Error("未找到可编辑的源文件");
        const response = await fetch(`/api/servers/${proto}/file?source=${encodeURIComponent(nextSource)}`);
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "资源文件加载失败");
        currentServerEditorProto = proto;
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
    currentServerEditorProto = "";
}

async function saveServerFileContent() {
    if (!currentServerFile?.editable || !currentServerSource || !currentServerEditorProto) return;
    const textarea = document.getElementById("serverFileEditor");
    const content = textarea?.value ?? "";
    try {
        const response = await fetch(`/api/servers/${currentServerEditorProto}/file?source=${encodeURIComponent(currentServerSource)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });
        const data = await response.json();
        if (!data.success) throw new Error(data.message || "资源文件保存失败");
        showNotification(data.message || "资源文件已保存", "success");
        await ensureServerSourceSelection(currentServerEditorProto, true);
        if (currentServerEditorProto === currentProto) {
            await loadServerGeoMap();
        }
        await reloadServerFileContent();
        loadAllServerCounts();
    } catch (error) {
        showNotification(`资源文件保存失败：${error.message}`, "error");
    }
}

async function reloadServerFileContent() {
    if (!currentServerSource || !currentServerEditorProto) return;
    await openServerEditorModal(currentServerSource, currentServerEditorProto);
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
        const response = await fetch(`/api/servers/${currentProto}`);
        const data = await response.json();
        if (data && data.success === false) throw new Error(data.message || "定位失败");
        const geoAreas = Array.isArray(data.geo_distribution) ? data.geo_distribution : [];
        const ips = Array.isArray(data.ips) ? data.ips : [];
        const isEmpty = !data || data.total === 0 || data.exists === false;
        updateGeoStats({
            total: data.total || 0,
            located_count: data.located_count || 0,
            unresolved_count: data.unresolved_count || 0,
            area_count: geoAreas.length
        });
        renderGeoUnresolved([]);
        lastGeoAreas = normalizeGeoAreas(geoAreas);
        lastGeoPoints = buildGeoPointsFromPool(ips, lastGeoAreas);
        serverResourceItems = buildServerResourceItems(lastGeoPoints);
        serverUnresolvedItems = [];
        serverUnresolvedCount = Number(data.unresolved_count) || 0;
        if (serverListFilterMode === "area" && !getSelectedArea()) {
            resetServerSelectionState();
        }
        if (serverListFilterMode === "ip" && selectedIp && !serverResourceItems.some((item) => item.ip === selectedIp)) {
            resetServerSelectionState();
        }
        await ensureServerMapShapes();
        renderServerWorkspace();
        if (isEmpty) {
            setMapStatus(data.message || "暂无该协议的质量 IP，请先执行扫描任务", false);
        } else if (!window.Globe) {
            setMapStatus("3D 地图库加载失败，已保留资源区域统计。", false);
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
        serverUnresolvedCount = 0;
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
        const areaPoint = lastGeoPoints.find((point) => activeArea.ips.includes(point.ip)
            && Number.isFinite(Number(point.lat)) && Number.isFinite(Number(point.lon)));
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
    const tcpSection = document.getElementById("tcpPktMethodSection");
    const sourceRow = document.getElementById("singleProtoSourceRow");
    if (tcpSection) tcpSection.style.display = (method === "tcp") ? "block" : "none";
    if (sourceRow) {
        sourceRow.style.display = method ? "flex" : "none";
    }
    if (!method) {
        singleSelectedSources = [];
        updateSingleSourceLabel();
    }
    if (method) loadReflectorCount([method]);
    updateWorkflowIndicators();
}

function updateProtocolSelection() {
    selectedProtocols = Array.from(document.querySelectorAll("#multiProtocolSection input[type='checkbox']:checked"))
        .map((input) => input.value);
    if (isMultiProtocol) {
        loadReflectorCount(selectedProtocols);
        const tcpSection = document.getElementById("tcpPktMethodSection");
        if (tcpSection) tcpSection.style.display = selectedProtocols.includes("tcp") ? "block" : "none";
    } else {
        const method = document.getElementById("method")?.value;
        loadReflectorCount(method ? [method] : ["memcached", "dns", "ntp"]);
    }
    updateWorkflowIndicators();
}

function saveConsoleFormSession() {
    const fields = FormPersistence.readFormFields("#testForm", CONSOLE_FIELD_MAP);
    fields.tcp_pkt_methods = FormPersistence.readCheckboxGroup("#tcpPktMethodSection");
    fields.multi_proto_selected = selectedProtocols.slice();
    fields.single_selected_sources = singleSelectedSources.slice();
    fields.multi_proto_sources = JSON.parse(JSON.stringify(multiProtoSelectedSources));
    fields.is_multi_protocol = isMultiProtocol;
    FormPersistence.save("session:console_form", fields, "session");
}

function restoreConsoleFormSession() {
    const data = FormPersistence.load("session:console_form", "session");
    if (!data) return false;
    FormPersistence.writeFormFields("#testForm", CONSOLE_FIELD_MAP, data);
    if (Array.isArray(data.tcp_pkt_methods)) {
        FormPersistence.writeCheckboxGroup("#tcpPktMethodSection", data.tcp_pkt_methods);
    }
    if (typeof data.is_multi_protocol === "boolean") {
        isMultiProtocol = data.is_multi_protocol;
        const toggle = document.getElementById("multi_protocol");
        if (toggle) toggle.checked = isMultiProtocol;
        const singleGroup = document.getElementById("singleMethodGroup");
        const multiSection = document.getElementById("multiProtocolSection");
        if (singleGroup) singleGroup.style.display = isMultiProtocol ? "none" : "block";
        if (multiSection) multiSection.style.display = isMultiProtocol ? "block" : "none";
    }
    if (Array.isArray(data.multi_proto_selected)) {
        selectedProtocols = data.multi_proto_selected;
        FormPersistence.writeCheckboxGroup("#multiProtocolSection", selectedProtocols);
    }
    if (Array.isArray(data.single_selected_sources)) {
        singleSelectedSources = data.single_selected_sources;
        updateSingleSourceLabel();
    }
    if (data.multi_proto_sources && typeof data.multi_proto_sources === "object") {
        multiProtoSelectedSources = data.multi_proto_sources;
        Object.entries(multiProtoSelectedSources).forEach(([proto, sources]) => {
            updateMultiProtoSourceLabel(proto, sources);
        });
    }
    updateProtocolSelection();
    updateMethodSettings();
    updateWorkflowIndicators();
    return true;
}

function saveConsoleFormPersist() {
    const fields = FormPersistence.readFormFields("#testForm", CONSOLE_FIELD_MAP);
    fields.tcp_pkt_methods = FormPersistence.readCheckboxGroup("#tcpPktMethodSection");
    fields.multi_proto_selected = selectedProtocols.slice();
    fields.single_selected_sources = singleSelectedSources.slice();
    fields.multi_proto_sources = JSON.parse(JSON.stringify(multiProtoSelectedSources));
    fields.is_multi_protocol = isMultiProtocol;
    FormPersistence.save("persist:last_successful:console", fields, "local");
}

function restoreConsoleFormPersist() {
    const data = FormPersistence.load("persist:last_successful:console", "local");
    if (!data) return false;
    FormPersistence.writeFormFields("#testForm", CONSOLE_FIELD_MAP, data);
    if (Array.isArray(data.tcp_pkt_methods)) {
        FormPersistence.writeCheckboxGroup("#tcpPktMethodSection", data.tcp_pkt_methods);
    }
    if (typeof data.is_multi_protocol === "boolean") {
        isMultiProtocol = data.is_multi_protocol;
        const toggle = document.getElementById("multi_protocol");
        if (toggle) toggle.checked = isMultiProtocol;
        const singleGroup = document.getElementById("singleMethodGroup");
        const multiSection = document.getElementById("multiProtocolSection");
        if (singleGroup) singleGroup.style.display = isMultiProtocol ? "none" : "block";
        if (multiSection) multiSection.style.display = isMultiProtocol ? "block" : "none";
    }
    if (Array.isArray(data.multi_proto_selected)) {
        selectedProtocols = data.multi_proto_selected;
        FormPersistence.writeCheckboxGroup("#multiProtocolSection", selectedProtocols);
    }
    if (Array.isArray(data.single_selected_sources)) {
        singleSelectedSources = data.single_selected_sources;
        updateSingleSourceLabel();
    }
    if (data.multi_proto_sources && typeof data.multi_proto_sources === "object") {
        multiProtoSelectedSources = data.multi_proto_sources;
        Object.entries(multiProtoSelectedSources).forEach(([proto, sources]) => {
            updateMultiProtoSourceLabel(proto, sources);
        });
    }
    updateProtocolSelection();
    updateMethodSettings();
    updateWorkflowIndicators();
    return true;
}

function clearConsoleFormSession() {
    FormPersistence.clear("session:console_form", "session");
}

function initConsoleFormPersistence() {
    const form = document.getElementById("testForm");
    if (!form) return;

    let hasSession = restoreConsoleFormSession();
    if (!hasSession) {
        const restored = restoreConsoleFormPersist();
        if (restored) {
            setTimeout(() => {
                showNotification("已自动填充上次成功配置", "info");
            }, 500);
        }
    }

    form.querySelectorAll("input, select, textarea").forEach((el) => {
        el.addEventListener("input", saveConsoleFormSession);
        el.addEventListener("change", saveConsoleFormSession);
    });
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
    loadReflectorCount(["memcached", "dns", "ntp", "tcp"]);
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
        // 收集每个协议的源文件选择
        data.protocol_sources = {};
        for (const proto of selectedProtocols) {
            data.protocol_sources[proto] = getMultiProtoSelectedSources(proto);
        }
        if (selectedProtocols.includes("tcp")) {
            const checked = document.querySelectorAll("#tcpPktMethodSection input[type='checkbox']:checked");
            data.tcp_pkt_methods = Array.from(checked).map(cb => cb.value);
        }
    } else {
        const method = document.getElementById("method")?.value;
        if (!method) {
            showNotification("请选择测试协议", "error");
            return;
        }
        data.method = method;
        data.selected_protocols = [method];
        data.protocol_sources = {};
        data.protocol_sources[method] = singleSelectedSources.length ? singleSelectedSources : null;
        if (method === "tcp") {
            const checked = document.querySelectorAll("#tcpPktMethodSection input[type='checkbox']:checked");
            data.tcp_pkt_methods = Array.from(checked).map(cb => cb.value);
        }
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
        saveConsoleFormPersist();
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
    clearConsoleFormSession();
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
    saveLatencyFormPersist();
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
    saveLatencyFormSession();
}

function saveLatencyFormSession() {
    const fields = {};
    const ipEl = document.getElementById("latencyTargetIp");
    const portEl = document.getElementById("latencyPort");
    if (ipEl) fields.target_ip = ipEl.value;
    if (portEl) fields.port = portEl.value;
    FormPersistence.save("session:latency_form", fields, "session");
}

function restoreLatencyFormSession() {
    const data = FormPersistence.load("session:latency_form", "session");
    if (!data) return false;
    const ipEl = document.getElementById("latencyTargetIp");
    const portEl = document.getElementById("latencyPort");
    if (ipEl && data.target_ip !== undefined) ipEl.value = data.target_ip;
    if (portEl && data.port !== undefined) portEl.value = data.port;
    return true;
}

function saveLatencyFormPersist() {
    const fields = {};
    const ipEl = document.getElementById("latencyTargetIp");
    const portEl = document.getElementById("latencyPort");
    if (ipEl) fields.target_ip = ipEl.value;
    if (portEl) fields.port = portEl.value;
    FormPersistence.save("persist:last_successful:latency", fields, "local");
}

function restoreLatencyFormPersist() {
    const data = FormPersistence.load("persist:last_successful:latency", "local");
    if (!data) return false;
    const ipEl = document.getElementById("latencyTargetIp");
    const portEl = document.getElementById("latencyPort");
    if (ipEl && data.target_ip !== undefined) ipEl.value = data.target_ip;
    if (portEl && data.port !== undefined) portEl.value = data.port;
    return true;
}

function initLatencyFormPersistence() {
    const ipEl = document.getElementById("latencyTargetIp");
    const portEl = document.getElementById("latencyPort");
    if (!ipEl && !portEl) return;

    const hasSession = restoreLatencyFormSession();
    if (!hasSession) {
        restoreLatencyFormPersist();
    }

    if (ipEl) {
        ipEl.addEventListener("input", saveLatencyFormSession);
        ipEl.addEventListener("change", saveLatencyFormSession);
    }
    if (portEl) {
        portEl.addEventListener("input", saveLatencyFormSession);
        portEl.addEventListener("change", saveLatencyFormSession);
    }
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
let ntpScanPollInterval = null;
let currentNtpRunId = null;
let currentNtpRuns = [];
let currentNtpSummary = null;
let currentMemcachedRunId = null;
let currentMemcachedRuns = [];
let currentMemcachedSummary = null;
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
            const location = (f.path || "").includes("attack_resources/shared/ip_lists") || (f.path || "").includes("attack_resources\\shared\\ip_lists")
                ? "共享目录"
                : "DNS 目录";
            const subDir = f.sub_dir ? ` · ${f.sub_dir}` : "";
            return `<option value="${escapeHtml(f.path)}">${escapeHtml(f.name)} · ${f.entry_count} 条 · ${location}${subDir}</option>`;
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
        const metaText = running
            ? "执行中"
            : (r.status === "error" ? "失败" : (r.status === "stopped" ? "已停止" : (r.summary?.timestamp ? "已完成" : "-")));
        return `<button type="button" class="tcp-run-item ${active ? "active" : ""}" data-run-id="${escapeHtml(r.run_id)}">
            <span class="tcp-run-item-main">
                <span>${escapeHtml(r.run_id)}</span>
                <span>优质: ${r.qualified_count || 0} IPs</span>
            </span>
            <span class="tcp-run-item-meta">
                <span>${metaText}</span>
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
    if (stage === "stopped") return "已停止";
    if (stage === "saving") return isRunning ? "保存中" : "已保存";
    if (stage === "filtering") return isRunning ? "筛选中" : "已筛选";
    if (stage === "scanning") return isRunning ? "测量中" : "已测量";
    if (stage === "loading") return isRunning ? "加载中" : "已加载";
    return isRunning ? "运行中" : "空闲";
}

function renderDnsStages(stats = {}, isRunning = false) {
    const stageList = document.getElementById("dnsStageList");
    if (!stageList) return;
    const stages = ["loading", "scanning", "filtering", "saving"];
    const stageLabels = ["加载候选 IP", "放大率测量", "按阈值筛选", "保存结果"];
    const stageStates = stats.stages || {};
    const currentStage = stats.current_stage || "";
    const finalStage = stats.stage || "";

    stageList.innerHTML = stages.map((stageName, index) => {
        const persistedStatus = stageStates[stageName]?.status;
        let state = "待开始";

        if (persistedStatus === "completed") {
            state = "已完成";
        } else if (persistedStatus === "failed") {
            state = "失败";
        } else if (persistedStatus === "stopped") {
            state = "已停止";
        } else if (persistedStatus === "running" || (isRunning && currentStage === stageName)) {
            state = "进行中";
        } else if (finalStage === "done") {
            state = "已完成";
        } else if (finalStage === "error") {
            const failedIndex = stages.indexOf(currentStage);
            if (failedIndex > index) state = "已完成";
            else if (failedIndex === index) state = "失败";
        } else if (finalStage === "stopped") {
            const stoppedIndex = stages.indexOf(currentStage);
            if (stoppedIndex > index) state = "已完成";
            else if (stoppedIndex === index) state = "已停止";
        }

        return `<div class="tcp-stage-item"><span>${stageLabels[index]}</span><strong>${state}</strong></div>`;
    }).join("");
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
        renderDnsStages(s, running);
        if (dnsStopBtn) dnsStopBtn.disabled = !running;
        if (dnsStartBtn) dnsStartBtn.disabled = running;

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
        const dnsArtifactsEl = document.getElementById("dnsArtifacts");
        dnsArtifactsEl.innerHTML = artifacts.length
            ? artifacts.map((a) => {
                const desc = getFileDescription(a.name, "dns");
                const infoIcon = desc
                    ? `<span class="file-info-icon" data-tooltip="${escapeHtml(desc)}" title="">ℹ️</span>`
                    : "";
                return `<button type="button" class="tcp-artifact-item tcp-file-button" data-dns-file-name="${escapeHtml(a.name)}"><span>${escapeHtml(a.name)}</span>${infoIcon}<strong>${formatBytes(a.size)}</strong></button>`;
            }).join("")
            : `<div class="info-text">暂无输出文件</div>`;
        document.querySelectorAll("[data-dns-file-name]").forEach((item) => {
            item.addEventListener("click", () => openDnsFileModal(item.getAttribute("data-dns-file-name")));
        });
        dnsArtifactsEl.querySelectorAll(".file-info-icon").forEach((icon) => {
            icon.addEventListener("click", (e) => e.stopPropagation());
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

const ATTACK_RESOURCE_PROTO_CONFIG = {
    tcp: {
        displayName: "TCP",
        apiBase: "/api/attack-resource/tcp",
        emptyLogText: "尚未选择 TCP 资源获取任务。",
        summaryCardIds: {
            status: "tcpStatus",
            run_id: "tcpRunId",
            method: "tcpRunMethod",
            target_host: "tcpRunHost"
        },
        controls: {
            start: "tcpStartBtn",
            stop: "tcpStopBtn",
            stopCleanup: "tcpStopCleanupBtn",
            refresh: "tcpRefreshBtn",
            clear: "tcpClearRunsBtn"
        },
        readForm: readUnifiedTcpForm,
        renderResources: renderUnifiedTcpResources,
        getSummaryValues(run) {
            return {
                status: getAttackResourceStatusText(run.status),
                run_id: run.run_id || "-",
                method: run.summary_stats?.method || run.config?.pkt_method || "-",
                target_host: run.summary_stats?.target_host || run.config?.target_host || "-"
            };
        },
        syncLegacyState(controller) {
            currentTcpRunId = controller.currentRunId;
            currentTcpRuns = controller.runs.map((run) => ({
                run_id: run.run_id,
                status: run.status,
                pkt_method: run.badge_text,
                target_host: run.secondary_text
            }));
            currentTcpSummary = controller.currentRun;
        }
    },
    dns: {
        displayName: "DNS",
        apiBase: "/api/attack-resource/dns",
        emptyLogText: "尚未选择 DNS 资源获取任务。",
        summaryCardIds: {
            status: "dnsStatus",
            run_id: "dnsRunId",
            stage: "dnsStage",
            progress: "dnsProgress"
        },
        controls: {
            start: "dnsStartBtn",
            stop: "dnsStopBtn",
            refresh: "dnsRefreshBtn",
            clear: "dnsClearRunsBtn"
        },
        readForm: readUnifiedDnsForm,
        renderResources: renderUnifiedDnsResources,
        initExtraControls() {
            document.getElementById("dnsDomainPresetBtn")?.addEventListener("click", fillDnsDomainPreset);
        },
        getSummaryValues(run) {
            return {
                status: getAttackResourceStatusText(run.status),
                run_id: run.run_id || "-",
                stage: (run.summary_stats?.stage || run.current_stage || "-").toUpperCase(),
                progress: run.progress?.label || "0/0"
            };
        },
        syncLegacyState(controller) {
            currentDnsRunId = controller.currentRunId;
            currentDnsRuns = controller.runs.map((run) => ({
                run_id: run.run_id,
                status: run.status,
                qualified_count: run.secondary_text
            }));
            currentDnsSummary = controller.currentRun;
        }
    },
    ntp: {
        displayName: "NTP",
        apiBase: "/api/attack-resource/ntp",
        emptyLogText: "尚未选择 NTP 资源获取任务。",
        summaryCardIds: {
            status: "ntpStatus",
            run_id: "ntpRunId",
            stage: "ntpStage",
            progress: "ntpProgress"
        },
        controls: {
            start: "ntpStartBtn",
            stop: "ntpStopBtn",
            refresh: "ntpRefreshBtn",
            clear: "ntpClearRunsBtn"
        },
        readForm: readUnifiedNtpForm,
        renderResources: renderUnifiedNtpResources,
        initExtraControls() {},
        getSummaryValues(run) {
            return {
                status: getAttackResourceStatusText(run.status),
                run_id: run.run_id || "-",
                stage: (run.summary_stats?.stage || run.current_stage || "-").toUpperCase(),
                progress: run.progress?.label || "0/0"
            };
        },
        syncLegacyState(controller) {
            currentNtpRunId = controller.currentRunId;
            currentNtpRuns = controller.runs.map((run) => ({
                run_id: run.run_id,
                status: run.status,
                qualified_count: run.secondary_text
            }));
            currentNtpSummary = controller.currentRun;
        }
    },
    memcached: {
        displayName: "Memcached",
        apiBase: "/api/attack-resource/memcached",
        emptyLogText: "尚未选择 Memcached 资源获取任务。",
        summaryCardIds: {
            status: "memcachedStatus",
            run_id: "memcachedRunId",
            stage: "memcachedStage",
            progress: "memcachedProgress"
        },
        controls: {
            start: "memcachedStartBtn",
            stop: "memcachedStopBtn",
            refresh: "memcachedRefreshBtn",
            clear: "memcachedClearRunsBtn"
        },
        readForm: readUnifiedMemcachedForm,
        renderResources: renderUnifiedMemcachedResources,
        getSummaryValues(run) {
            return {
                status: getAttackResourceStatusText(run.status),
                run_id: run.run_id || "-",
                stage: (run.summary_stats?.stage || run.current_stage || "-").toUpperCase(),
                progress: run.progress?.label || "0/0"
            };
        },
        syncLegacyState(controller) {
            currentMemcachedRunId = controller.currentRunId;
            currentMemcachedRuns = controller.runs.map((run) => ({
                run_id: run.run_id,
                status: run.status,
                qualified_count: run.secondary_text
            }));
            currentMemcachedSummary = controller.currentRun;
        }
    }
};

class AttackResourceTaskController {
    constructor(proto, config) {
        this.proto = proto;
        this.config = config;
        this.currentRunId = null;
        this.currentRun = null;
        this.runs = [];
        this.activeRunIds = [];
        this.pollTimer = null;
    }

    init() {
        this.bindControls();
        this.config.initExtraControls?.();
        this.loadResources();
        return this.refresh();
    }

    bindControls() {
        this.bindButton(this.config.controls.start, () => this.start());
        this.bindButton(this.config.controls.stop, () => this.stop(false));
        this.bindButton(this.config.controls.refresh, () => this.refresh());
        this.bindButton(this.config.controls.clear, () => this.clear());
    }

    bindButton(id, handler) {
        const element = document.getElementById(id);
        if (!element) return;
        element.onclick = async (event) => {
            event.preventDefault();
            await handler();
        };
    }

    getPanel() {
        return document.querySelector(`.attack-resource-panel[data-proto-panel="${this.proto}"]`);
    }

    getRole(role) {
        return this.getPanel()?.querySelector(`[data-role="${role}"]`);
    }

    _legacyIdMap = {
        "run-list": { tcp: "tcpRunList", dns: "dnsRunList", memcached: "memcachedRunList", ntp: "ntpRunList" },
        "pipeline-log": { tcp: "tcpPipelineLog", dns: "dnsPipelineLog", memcached: "memcachedPipelineLog", ntp: "ntpPipelineLog" },
        "runtime-error": { tcp: "tcpRuntimeError", dns: "dnsRuntimeError", memcached: "memcachedRuntimeError", ntp: "ntpRuntimeError" },
        "detail-meta": { tcp: "tcpRunMeta", dns: "dnsRunMeta", memcached: "memcachedRunMeta", ntp: "ntpRunMeta" },
        "stage-list": { tcp: "tcpStages", dns: "dnsStageList", memcached: "memcachedStageList", ntp: "ntpStageList" },
        "artifact-list": { tcp: "tcpArtifacts", dns: "dnsArtifacts", memcached: "memcachedArtifacts", ntp: "ntpArtifacts" },
        "result-preview": { tcp: "tcpQualifiedPreview", dns: "dnsQualifiedPreview", memcached: "memcachedQualifiedPreview", ntp: "ntpQualifiedPreview" }
    };

    _getElement(role) {
        const el = this.getRole(role);
        if (el) return el;
        const idMap = this._legacyIdMap[role];
        if (idMap && idMap[this.proto]) {
            return document.getElementById(idMap[this.proto]);
        }
        return null;
    }

    async loadResources() {
        try {
            const response = await fetch(`${this.config.apiBase}/resources`);
            const data = await response.json();
            if (!data.success) throw new Error(data.message || `${this.config.displayName} 资源加载失败`);
            this.config.renderResources?.(data.resources || []);
            this.restoreFormState();
            this.bindFormPersistence();
            updateWorkflowIndicators();
        } catch (error) {
            showNotification(`${this.config.displayName} 资源加载失败：${error.message}`, "error");
        }
    }

    getSessionKey() {
        return `session:attack_resource:${this.proto}`;
    }

    getPersistKey() {
        return `persist:last_successful:attack_resource:${this.proto}`;
    }

    saveFormSession() {
        const fieldMap = ATTACK_RESOURCE_FIELD_MAPS[this.proto];
        if (!fieldMap) return;
        const panel = this.getPanel();
        if (!panel) return;
        const fields = {};
        for (const [key, selector] of Object.entries(fieldMap)) {
            const el = panel.querySelector(selector);
            if (!el) continue;
            if (el.type === "checkbox") {
                fields[key] = el.checked;
            } else {
                fields[key] = el.value;
            }
        }
        if (this.proto === "tcp") {
            fields.pkt_methods = FormPersistence.readCheckboxGroup("#tcpMethodChecks");
        }
        FormPersistence.save(this.getSessionKey(), fields, "session");
    }

    restoreFormSession() {
        const fieldMap = ATTACK_RESOURCE_FIELD_MAPS[this.proto];
        if (!fieldMap) return false;
        const data = FormPersistence.load(this.getSessionKey(), "session");
        if (!data) return false;
        const panel = this.getPanel();
        if (!panel) return false;
        for (const [key, selector] of Object.entries(fieldMap)) {
            if (!(key in data)) continue;
            const el = panel.querySelector(selector);
            if (!el) continue;
            if (el.type === "checkbox") {
                el.checked = Boolean(data[key]);
            } else {
                el.value = data[key];
            }
            el.dispatchEvent(new Event("change", { bubbles: true }));
            el.dispatchEvent(new Event("input", { bubbles: true }));
        }
        if (this.proto === "tcp" && Array.isArray(data.pkt_methods)) {
            FormPersistence.writeCheckboxGroup("#tcpMethodChecks", data.pkt_methods);
        }
        return true;
    }

    saveFormPersist() {
        const fieldMap = ATTACK_RESOURCE_FIELD_MAPS[this.proto];
        if (!fieldMap) return;
        const panel = this.getPanel();
        if (!panel) return;
        const fields = {};
        for (const [key, selector] of Object.entries(fieldMap)) {
            const el = panel.querySelector(selector);
            if (!el) continue;
            if (el.type === "checkbox") {
                fields[key] = el.checked;
            } else {
                fields[key] = el.value;
            }
        }
        if (this.proto === "tcp") {
            fields.pkt_methods = FormPersistence.readCheckboxGroup("#tcpMethodChecks");
        }
        FormPersistence.save(this.getPersistKey(), fields, "local");
    }

    restoreFormPersist() {
        const fieldMap = ATTACK_RESOURCE_FIELD_MAPS[this.proto];
        if (!fieldMap) return false;
        const data = FormPersistence.load(this.getPersistKey(), "local");
        if (!data) return false;
        const panel = this.getPanel();
        if (!panel) return false;
        for (const [key, selector] of Object.entries(fieldMap)) {
            if (!(key in data)) continue;
            const el = panel.querySelector(selector);
            if (!el) continue;
            if (el.type === "checkbox") {
                el.checked = Boolean(data[key]);
            } else {
                el.value = data[key];
            }
            el.dispatchEvent(new Event("change", { bubbles: true }));
            el.dispatchEvent(new Event("input", { bubbles: true }));
        }
        if (this.proto === "tcp" && Array.isArray(data.pkt_methods)) {
            FormPersistence.writeCheckboxGroup("#tcpMethodChecks", data.pkt_methods);
        }
        return true;
    }

    clearFormSession() {
        FormPersistence.clear(this.getSessionKey(), "session");
    }

    restoreFormState() {
        const hasSession = this.restoreFormSession();
        if (!hasSession) {
            this.restoreFormPersist();
        }
    }

    bindFormPersistence() {
        const panel = this.getPanel();
        if (!panel || panel.dataset.persistenceBound) return;
        panel.dataset.persistenceBound = "1";
        panel.querySelectorAll("input, select, textarea").forEach((el) => {
            el.addEventListener("input", () => this.saveFormSession());
            el.addEventListener("change", () => this.saveFormSession());
        });
    }

    async start() {
        const payload = this.config.readForm();
        if (!payload) return;
        const startButton = document.getElementById(this.config.controls.start);
        if (startButton) startButton.disabled = true;
        try {
            const response = await fetch(`${this.config.apiBase}/runs`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || `启动 ${this.config.displayName} 资源获取失败`);
            }
            const runIds = data.run_ids || [];
            if (runIds.length) this.currentRunId = runIds[0];
            this.saveFormPersist();
            showNotification(data.message || `${this.config.displayName} 资源获取任务已创建`, "success");
            this.startPolling();
            await this.refresh();
        } catch (error) {
            showNotification(`${this.config.displayName} 启动失败：${error.message}`, "error");
        } finally {
            if (startButton && !this.currentRun?.is_running) startButton.disabled = false;
        }
    }

    async stop(cleanup = false) {
        if (!this.currentRunId) {
            showNotification(`尚未选择 ${this.config.displayName} 资源获取任务`, "error");
            return;
        }
        try {
            const response = await fetch(`${this.config.apiBase}/runs/${encodeURIComponent(this.currentRunId)}/stop`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cleanup })
            });
            const data = await response.json();
            if (!data.success) throw new Error(data.message || "停止失败");
            showNotification(data.message || `已请求停止 ${this.config.displayName} 资源获取`, "info");
            await this.refresh();
        } catch (error) {
            showNotification(`${this.config.displayName} 停止失败：${error.message}`, "error");
        }
    }

    async clear() {
        if (!confirm(`清除所有已结束 ${this.config.displayName} 资源获取记录及产物？运行中的任务会保留。`)) {
            return;
        }
        try {
            const response = await fetch(`${this.config.apiBase}/runs`, { method: "DELETE" });
            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || "清除失败");
            if ((data.deleted || []).includes(this.currentRunId)) this.currentRunId = null;
            showNotification(data.message || "记录已清除", "success");
            await this.refresh();
        } catch (error) {
            showNotification(`${this.config.displayName} 清除记录失败：${error.message}`, "error");
        }
    }

    startPolling() {
        this.stopPolling();
        this.pollTimer = setInterval(() => {
            this.refresh();
        }, 1200);
    }

    stopPolling() {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
        }
    }

    async refresh() {
        try {
            const response = await fetch(`${this.config.apiBase}/runs`);
            const data = await response.json();
            if (!data.success) throw new Error(data.message || "加载任务列表失败");
            this.runs = Array.isArray(data.runs) ? data.runs : [];
            this.activeRunIds = Array.isArray(data.active_run_ids) ? data.active_run_ids : [];
            this.renderRunList();
            const preferred = this.pickPreferredRun();
            if (!preferred) {
                this.renderEmptyState();
                this.syncLegacyState();
                updateWorkflowIndicators();
                return;
            }
            this.currentRunId = preferred.run_id;
            this.renderRunList();
            await this.loadRunDetail(this.currentRunId);
            if (!this.activeRunIds.length) this.stopPolling();
            else this.startPolling();
            this.syncLegacyState();
            updateWorkflowIndicators();
        } catch (error) {
            console.warn(`${this.config.displayName} 资源获取刷新失败`, error);
        }
    }

    pickPreferredRun() {
        const selected = this.currentRunId ? this.runs.find((run) => run.run_id === this.currentRunId) : null;
        if (selected) return selected;
        if (this.activeRunIds.length) {
            const active = this.runs.find((run) => run.run_id === this.activeRunIds[0]);
            if (active) return active;
        }
        return this.runs[0] || null;
    }

    renderRunList() {
        const container = this._getElement("run-list");
        if (!container) return;
        if (!this.runs.length) {
            container.innerHTML = `<div class="info-text">暂无 ${this.config.displayName} 资源获取任务。</div>`;
            return;
        }
        container.innerHTML = this.runs.map((run) => {
            const active = run.run_id === this.currentRunId;
            const statusText = getAttackResourceStatusText(run.status);
            return `
                <button type="button" class="tcp-run-item ${active ? "active" : ""}" data-run-id="${escapeHtml(run.run_id)}">
                    <span class="tcp-run-item-main">
                        <span>${escapeHtml(run.primary_text || run.run_id)}</span>
                        <span>${escapeHtml(run.secondary_text || "-")}</span>
                    </span>
                    <span class="tcp-run-item-meta">
                        <span>${escapeHtml(run.badge_text || "-")}</span>
                        <strong>${escapeHtml(statusText)}</strong>
                    </span>
                </button>
            `;
        }).join("");
        container.querySelectorAll("[data-run-id]").forEach((item) => {
            item.addEventListener("click", async () => {
                this.currentRunId = item.getAttribute("data-run-id");
                this.renderRunList();
                await this.loadRunDetail(this.currentRunId);
                this.syncLegacyState();
                updateWorkflowIndicators();
            });
        });
    }

    async loadRunDetail(runId) {
        const response = await fetch(`${this.config.apiBase}/runs/${encodeURIComponent(runId)}`);
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.message || "加载任务详情失败");
        }
        this.currentRun = data.run;
        await this.loadRunLog(runId);
        this.renderCurrentRun();
    }

    async loadRunLog(runId) {
        try {
            const response = await fetch(`${this.config.apiBase}/runs/${encodeURIComponent(runId)}/logs?tail=200`);
            const data = await response.json();
            if (data.success) {
                const logBox = this._getElement("pipeline-log");
                if (logBox) logBox.textContent = data.log || this.config.emptyLogText;
            }
        } catch (error) {
            console.warn(`${this.config.displayName} 日志加载失败`, error);
        }
    }

    renderCurrentRun() {
        const run = this.currentRun;
        if (!run) {
            this.renderEmptyState();
            return;
        }
        this.renderSummaryCards(run);
        this.renderDetailMeta(run.detail_items || []);
        this.renderStages(run.stages || []);
        this.renderArtifacts(run.artifacts || []);
        this.renderResultPreview(run.result_preview);
        const runtimeError = this._getElement("runtime-error");
        if (runtimeError) runtimeError.textContent = run.runtime_error ? `失败原因：${run.runtime_error}` : "";
        const startButton = document.getElementById(this.config.controls.start);
        const stopButton = document.getElementById(this.config.controls.stop);
        if (startButton) startButton.disabled = Boolean(run.is_running);
        if (stopButton) stopButton.disabled = !run.is_running;
        if (this.config.controls.stopCleanup) {
            const stopCleanupButton = document.getElementById(this.config.controls.stopCleanup);
            if (stopCleanupButton) stopCleanupButton.disabled = !run.is_running;
        }
    }

    renderSummaryCards(run) {
        const values = this.config.getSummaryValues(run);
        Object.entries(this.config.summaryCardIds).forEach(([key, id]) => {
            setText(id, values[key] ?? "-");
        });
    }

    renderDetailMeta(items) {
        const container = this._getElement("detail-meta");
        if (!container) return;
        container.innerHTML = items.map((item) => `
            <div class="tcp-run-meta-item">
                <span>${escapeHtml(String(item.label || "-"))}</span>
                <strong>${escapeHtml(String(item.value ?? "-"))}</strong>
            </div>
        `).join("");
    }

    renderStages(stages) {
        const container = this._getElement("stage-list");
        if (!container) return;
        container.innerHTML = stages.map((stage) => `
            <div class="tcp-stage-item">
                <span>${escapeHtml(stage.label || stage.key || "-")}</span>
                <strong>${escapeHtml(getAttackResourceStatusText(stage.status))}</strong>
            </div>
        `).join("");
    }

    renderArtifacts(artifacts) {
        const container = this._getElement("artifact-list");
        if (!container) return;
        if (!artifacts.length) {
            container.innerHTML = `<div class="info-text">暂无输出文件。</div>`;
            return;
        }
        container.innerHTML = artifacts.map((artifact) => {
            const desc = getFileDescription(artifact.name, this.proto);
            const infoIcon = desc
                ? `<span class="file-info-icon" data-tooltip="${escapeHtml(desc)}" title="">ℹ️</span>`
                : "";
            return `<button type="button" class="tcp-artifact-item tcp-file-button" data-file-name="${escapeHtml(artifact.name)}">
                <span>${escapeHtml(artifact.name)}</span>${infoIcon}
                <strong>${formatBytes(artifact.size || 0)}</strong>
            </button>`;
        }).join("");
        container.querySelectorAll("[data-file-name]").forEach((item) => {
            item.addEventListener("click", () => this.openFile(item.getAttribute("data-file-name")));
        });
        container.querySelectorAll(".file-info-icon").forEach((icon) => {
            icon.addEventListener("click", (e) => e.stopPropagation());
        });
    }

    renderResultPreview(resultPreview) {
        const container = this._getElement("result-preview");
        if (!container) return;
        if (!resultPreview) {
            container.textContent = "";
            return;
        }
        if (resultPreview.type === "list") {
            const items = Array.isArray(resultPreview.items) ? resultPreview.items : [];
            if (!items.length) {
                container.textContent = resultPreview.empty_text || "暂无结果预览。";
                return;
            }
            container.innerHTML = `<strong>${escapeHtml(resultPreview.title || "结果预览")}</strong><br>${items.map((item) => escapeHtml(item)).join("<br>")}${resultPreview.total > items.length ? `<br>共 ${resultPreview.total} 条` : ""}`;
            return;
        }
        container.textContent = "";
    }

    renderEmptyState() {
        this.currentRun = null;
        this.currentRunId = null;
        this.renderSummaryCards({
            status: "idle",
            run_id: "-",
            summary_stats: { method: "-", target_host: "-", stage: "-", progress: "0/0" },
            progress: { label: "0/0" }
        });
        this.renderDetailMeta([]);
        this.renderStages([]);
        this.renderArtifacts([]);
        this.renderResultPreview(null);
        const logBox = this._getElement("pipeline-log");
        if (logBox) logBox.textContent = this.config.emptyLogText;
        const runtimeError = this._getElement("runtime-error");
        if (runtimeError) runtimeError.textContent = "";
        const startButton = document.getElementById(this.config.controls.start);
        const stopButton = document.getElementById(this.config.controls.stop);
        if (startButton) startButton.disabled = false;
        if (stopButton) stopButton.disabled = true;
        if (this.config.controls.stopCleanup) {
            const stopCleanupButton = document.getElementById(this.config.controls.stopCleanup);
            if (stopCleanupButton) stopCleanupButton.disabled = true;
        }
    }

    async openFile(filename) {
        if (!this.currentRunId || !filename) return;
        try {
            const response = await fetch(`${this.config.apiBase}/runs/${encodeURIComponent(this.currentRunId)}/files/${encodeURIComponent(filename)}`);
            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || "文件加载失败");
            currentAttackResourceFile = {
                proto: this.proto,
                runId: this.currentRunId,
                ...data.file
            };
            renderAttackResourceFileModal(currentAttackResourceFile);
            const modal = document.getElementById("tcpFileModal");
            if (modal) modal.hidden = false;
        } catch (error) {
            showNotification(`文件加载失败：${error.message}`, "error");
        }
    }

    syncLegacyState() {
        this.config.syncLegacyState?.(this);
    }
}

function initAttackResourceTaskFramework() {
    if (attackResourceTaskFrameworkInitialized) return;
    attackResourceTaskFrameworkInitialized = true;
    bindTcpModalControls();
    Object.entries(ATTACK_RESOURCE_PROTO_CONFIG).forEach(([proto, config]) => {
        attackResourceControllers[proto] = new AttackResourceTaskController(proto, config);
    });
    Object.values(attackResourceControllers).forEach((controller) => controller.init());
}

function readUnifiedTcpForm() {
    const checkedMethods = Array.from(document.querySelectorAll('#tcpMethodChecks input[type="checkbox"]:checked'))
        .map((input) => input.value);
    const payload = {
        ip_file: document.getElementById("tcpIpFile")?.value || "",
        target_host: document.getElementById("tcpTargetHost")?.value.trim() || "",
        pkt_method: document.getElementById("tcpPktMethod")?.value || "PSH",
        pkt_methods: checkedMethods.length ? checkedMethods : undefined,
        scan_rate: readNumber("tcpScanRate", 2500),
        ttl: readNumber("tcpTtl", 255),
        scan_count: readNumber("tcpScanCount", 10),
        result_limit: readNumberAllowZero("tcpResultLimit", 30),
        length_threshold: readNumberAllowZero("tcpLengthThreshold", 2000),
        min_amplification: parseFloat(document.getElementById("tcpMinAmplification")?.value) || 2.0,
        min_success_rate: parseFloat(document.getElementById("tcpMinSuccessRate")?.value) || 50.0,
        network_interface: document.getElementById("tcpNetworkInterface")?.value.trim() || "eth0",
        dry_run: Boolean(document.getElementById("tcpDryRun")?.checked)
    };
    if (!payload.ip_file || !payload.target_host) {
        showNotification("TCP 资源获取需要选择 IP 资源并填写目标主机", "error");
        return null;
    }
    if (!checkedMethods.length && !payload.pkt_method) {
        showNotification("请至少选择一种报文方法", "error");
        return null;
    }
    return payload;
}

function readUnifiedDnsForm() {
    return {
        ip_file: document.getElementById("dnsIpFile")?.value || "",
        test_domains: document.getElementById("dnsTestDomains")?.value || "",
        query_type: document.getElementById("dnsQueryType")?.value || "TXT",
        use_dnssec: document.getElementById("dnsUseDnssec")?.value === "1",
        concurrency: Number(document.getElementById("dnsConcurrency")?.value) || 80,
        timeout_sec: parseFloat(document.getElementById("dnsTimeout")?.value) || 3.0,
        min_amplification: parseFloat(document.getElementById("dnsMinAmplification")?.value) || 3.0,
        min_reliability: parseFloat(document.getElementById("dnsMinReliability")?.value) || 50
    };
}

function renderUnifiedTcpResources(resources = []) {
    const select = document.getElementById("tcpIpFile");
    if (!select) return;
    if (!resources.length) {
        select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
        return;
    }
    select.innerHTML = resources.map((file) => {
        const location = (file.path || "").includes("shared/ip_lists") || (file.path || "").includes("shared\\ip_lists") ? "共享目录" : "TCP 目录";
        const subDir = file.sub_dir ? ` · ${file.sub_dir}` : "";
        return `<option value="${escapeHtml(file.path || "")}">${escapeHtml(file.name || file.filename)} · ${file.entry_count || file.non_empty_lines || 0} 条 · ${location}${subDir}</option>`;
    }).join("");
}

function renderUnifiedDnsResources(resources = []) {
    const select = document.getElementById("dnsIpFile");
    if (!select) return;
    if (!resources.length) {
        select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
        updateDnsIpFileSummary([]);
        return;
    }
    select.innerHTML = resources.map((file) => {
        const location = (file.path || "").includes("shared/ip_lists") || (file.path || "").includes("shared\\ip_lists") ? "共享目录" : "DNS 目录";
        const subDir = file.sub_dir ? ` · ${file.sub_dir}` : "";
        return `<option value="${escapeHtml(file.path || "")}">${escapeHtml(file.name)} · ${file.entry_count || 0} 条 · ${location}${subDir}</option>`;
    }).join("");
    updateDnsIpFileSummary(resources);
}

function readUnifiedNtpForm() {
    return {
        ip_file: document.getElementById("ntpIpFile")?.value || "",
        probe_action: document.getElementById("ntpProbeAction")?.value || "both",
        concurrency: Number(document.getElementById("ntpConcurrency")?.value) || 50,
        timeout_sec: parseFloat(document.getElementById("ntpTimeout")?.value) || 3.0,
        min_amplification: parseFloat(document.getElementById("ntpMinAmplification")?.value) || 50.0,
        min_availability: parseFloat(document.getElementById("ntpMinAvailability")?.value) || 30
    };
}

function renderUnifiedNtpResources(resources = []) {
    const select = document.getElementById("ntpIpFile");
    if (!select) return;
    if (!resources.length) {
        select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
        updateNtpIpFileSummary([]);
        return;
    }
    select.innerHTML = resources.map((file) => {
        const location = (file.path || "").includes("attack_resources/shared/ip_lists") || (file.path || "").includes("attack_resources\\shared\\ip_lists") ? "共享目录" : "NTP 目录";
        const subDir = file.sub_dir ? ` · ${file.sub_dir}` : "";
        return `<option value="${escapeHtml(file.path || "")}">${escapeHtml(file.name)} · ${file.entry_count || 0} 条 · ${location}${subDir}</option>`;
    }).join("");
    updateNtpIpFileSummary(resources);
}

function updateNtpIpFileSummary(resources = []) {
    const summary = document.getElementById("ntpIpFileSummary");
    if (!summary) return;
    if (!resources.length) {
        summary.textContent = "未找到候选 IP 文件，请在共享 IP 资源目录中放置 .txt 文件。";
        return;
    }
    const total = resources.reduce((sum, r) => sum + (r.entry_count || 0), 0);
    summary.textContent = `共 ${resources.length} 个资源文件，${total} 条候选 IP。`;
}

function readUnifiedMemcachedForm() {
    return {
        ip_file: document.getElementById("memcachedIpFile")?.value || "",
        cmd_type: document.getElementById("memcachedCmdType")?.value || "get",
        data_size_kb: Number(document.getElementById("memcachedDataSizeKb")?.value) || 300,
        concurrency: Number(document.getElementById("memcachedConcurrency")?.value) || 50,
        timeout_sec: parseFloat(document.getElementById("memcachedTimeout")?.value) || 3.0,
        min_amplification: parseFloat(document.getElementById("memcachedMinAmplification")?.value) || 10.0,
        min_reliability: parseFloat(document.getElementById("memcachedMinReliability")?.value) || 50
    };
}

function renderUnifiedMemcachedResources(resources = []) {
    const select = document.getElementById("memcachedIpFile");
    if (!select) return;
    if (!resources.length) {
        select.innerHTML = `<option value="">暂无可用 IP 资源</option>`;
        updateMemcachedIpFileSummary([]);
        return;
    }
    select.innerHTML = resources.map((file) => {
        const location = (file.path || "").includes("attack_resources/shared/ip_lists") || (file.path || "").includes("attack_resources\\shared\\ip_lists") ? "共享目录" : "Memcached 目录";
        const subDir = file.sub_dir ? ` · ${file.sub_dir}` : "";
        return `<option value="${escapeHtml(file.path || "")}">${escapeHtml(file.name)} · ${file.entry_count || 0} 条 · ${location}${subDir}</option>`;
    }).join("");
    updateMemcachedIpFileSummary(resources);
}

function updateMemcachedIpFileSummary(resources = []) {
    const summary = document.getElementById("memcachedIpFileSummary");
    if (!summary) return;
    if (!resources.length) {
        summary.textContent = "未找到候选 IP 文件，请在共享 IP 资源目录中放置 .txt 文件。";
        return;
    }
    const total = resources.reduce((sum, r) => sum + (r.entry_count || 0), 0);
    summary.textContent = `共 ${resources.length} 个资源文件，${total} 条候选 IP。`;
}

function getAttackResourceStatusText(status) {
    return {
        idle: "空闲",
        running: "运行中",
        stopping: "停止中",
        stopped: "已停止",
        completed: "已完成",
        failed: "失败",
        error: "失败",
        skipped: "已跳过",
        pending: "等待中",
        unknown: "未知"
    }[status] || status || "未知";
}

function getAttackResourceRunCount(proto = currentAttackResourceProto) {
    return attackResourceControllers[proto]?.runs?.length || 0;
}

function getCurrentAttackResourceRun(proto = currentAttackResourceProto) {
    return attackResourceControllers[proto]?.currentRun || null;
}

function renderAttackResourceFileModal(file) {
    const title = document.getElementById("tcpFileModalTitle");
    const body = document.getElementById("tcpFileModalBody");
    const saveBtn = document.getElementById("tcpFileSaveBtn");
    const reloadBtn = document.getElementById("tcpFileReloadBtn");
    if (title) title.textContent = file.name || "文件内容";
    if (reloadBtn) reloadBtn.disabled = false;
    if (file.kind === "db" || file.type === "db") {
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

function closeTcpFileModal() {
    const modal = document.getElementById("tcpFileModal");
    if (modal) modal.hidden = true;
    currentAttackResourceFile = null;
    currentTcpFile = null;
    currentDnsFile = null;
}

async function saveTcpFileContent() {
    if (!currentAttackResourceFile?.editable) return;
    const textarea = document.getElementById("tcpFileEditor");
    const content = textarea?.value ?? "";
    try {
        const response = await fetch(`/api/attack-resource/${currentAttackResourceFile.proto}/runs/${encodeURIComponent(currentAttackResourceFile.runId)}/files/${encodeURIComponent(currentAttackResourceFile.name)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || "文件保存失败");
        showNotification(data.message || "文件已保存", "success");
        await attackResourceControllers[currentAttackResourceFile.proto]?.refresh();
        await reloadTcpFileContent();
    } catch (error) {
        showNotification(`文件保存失败：${error.message}`, "error");
    }
}

async function reloadTcpFileContent() {
    if (!currentAttackResourceFile?.name) return;
    await attackResourceControllers[currentAttackResourceFile.proto]?.openFile(currentAttackResourceFile.name);
}

async function openTcpFileModal(filename) {
    await attackResourceControllers.tcp?.openFile(filename);
}

async function openDnsFileModal(filename) {
    await attackResourceControllers.dns?.openFile(filename);
}

async function initTcpScan() {
    initAttackResourceTaskFramework();
}

async function refreshTcpScan() {
    await attackResourceControllers.tcp?.refresh();
}

async function startTcpScan() {
    await attackResourceControllers.tcp?.start();
}

async function stopTcpScan(cleanup = false) {
    await attackResourceControllers.tcp?.stop(cleanup);
}

async function clearTcpRunRecords() {
    await attackResourceControllers.tcp?.clear();
}

function initDnsScanView() {
    initAttackResourceTaskFramework();
}

async function refreshDnsScan() {
    await attackResourceControllers.dns?.refresh();
}

async function startDnsScan() {
    await attackResourceControllers.dns?.start();
}

async function stopDnsScan() {
    await attackResourceControllers.dns?.stop(false);
}

async function clearDnsRunRecords() {
    await attackResourceControllers.dns?.clear();
}

function getWorkflowState() {
    const hasResourceRecord = getAttackResourceRunCount() > 0;
    const resourceTotal = getCurrentResourceTotal();
    const configReady = isConsoleConfigReady();
    const hasRunningConfig = Boolean(latestStatusSnapshot?.config?.target_ip);
    const hasLatencySample = latencyDataPoints.some((point) => point.value !== undefined);
    const filterTitle = document.getElementById("serverFilterTitle")?.innerText || "全部资源";

    let resourceState = "not_started";
    if (currentView === "attack-resources" && !hasResourceRecord) {
        resourceState = "in_progress";
    } else if (hasResourceRecord) {
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

function getWorkflowStepMessage(workflow, step) {
    if (step === "resource") {
        const count = getAttackResourceRunCount();
        return count
            ? `当前已存在 ${count} 个 ${getMethodText(currentAttackResourceProto)} 资源任务记录，可以继续查看结果或直接进入资源池 / 控制台。`
            : "建议先完成资源获取；如果当前资源池已经可用，也可以直接跳到后续步骤。";
    }
    if (step === "pool") {
        return `当前资源池已识别 ${getCurrentResourceTotal()} 条资源，筛选视图为“${document.getElementById("serverFilterTitle")?.innerText || "全部资源"}”。`;
    }
    if (step === "console") {
        return isConsoleConfigReady()
            ? "控制台参数已经具备启动条件，可以直接发起测试。"
            : "这里负责配置目标、时长、线程和协议组合，熟练用户也可以直接从这里开始。";
    }
    return isMonitoringLatency
        ? "延迟监控正在采样中，可以继续观察基准延迟、最新延迟和变化趋势。"
        : "延迟监控不是必选步骤，但对观察链路扰动和效果变化很有帮助。";
}

function renderAttackResourceSummary() {
    const run = getCurrentAttackResourceRun();
    setText("attackResourcesActiveProto", getMethodText(currentAttackResourceProto).toUpperCase());
    setText("attackResourcesTcpStatus", "已接入");
    const taskText = run ? `${run.run_id} · ${getAttackResourceStatusText(run.status)}` : "暂无任务";
    setText("attackResourcesLastTask", taskText);
    const fileCount = Array.isArray(run?.artifacts) ? run.artifacts.length : 0;
    setText("attackResourcesArtifactSummary", fileCount ? `${fileCount} 个输出文件` : "暂无输出");
    setText("workflowSummaryResourceProto", getMethodText(currentAttackResourceProto).toUpperCase());
    setText("workflowSummaryResourceTask", taskText);
}

// ===== 文件管理模块 =====
const FileSystemUi = (() => {
    let currentPath = "";       // 当前所在目录的相对路径（相对项目根，POSIX 风格）
    let rootName = "项目根";    // 项目根目录显示名（仅 basename）
    let currentFile = null;     // 当前在编辑器中打开的文件对象
    let originalContent = "";   // 上次加载/保存后的原始内容
    let dirty = false;          // 编辑器内容是否被修改
    let rootLoaded = false;

    // ---------- 工具函数 ----------
    function formatSize(bytes) {
        if (bytes == null) return "—";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
    }

    function formatTime(iso) {
        if (!iso) return "—";
        try {
            const d = new Date(iso);
            if (isNaN(d.getTime())) return iso;
            return d.toLocaleString("zh-CN", { hour12: false });
        } catch { return iso; }
    }

    function encodePath(rel) {
        if (!rel) return "";
        return rel.split("/").map(encodeURIComponent).join("/");
    }

    function parentDir(rel) {
        if (!rel) return "";
        const idx = rel.lastIndexOf("/");
        return idx >= 0 ? rel.substring(0, idx) : "";
    }

    function joinPath(dir, name) {
        return dir ? `${dir}/${name}` : name;
    }

    // ---------- API 调用 ----------
    async function apiGet(endpoint) {
        const resp = await fetch(`/api/files${endpoint}`);
        return resp.json().catch(() => ({ success: false, message: "响应解析失败" }));
    }

    async function apiJson(endpoint, options) {
        const resp = await fetch(`/api/files${endpoint}`, options);
        return resp.json().catch(() => ({ success: false, message: "响应解析失败" }));
    }

    async function fetchRoot() {
        const data = await apiGet("/root");
        if (data.success && data.root) {
            rootName = data.root.name || "项目根";
            rootLoaded = true;
        }
    }

    async function fetchTree(path) {
        const q = path ? `?path=${encodePath(path)}` : "";
        return apiGet(`/tree${q}`);
    }

    async function fetchFile(path) {
        return apiGet(`/file?path=${encodePath(path)}`);
    }

    async function saveFile(path, content) {
        return apiJson(`/file?path=${encodePath(path)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });
    }

    async function createItem(path, type, content) {
        return apiJson(`/file`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path, type, content: content || "" })
        });
    }

    async function deleteItem(path) {
        return apiJson(`/file?path=${encodePath(path)}`, { method: "DELETE" });
    }

    async function renameItem(path, newPath) {
        return apiJson(`/rename`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path, new_path: newPath })
        });
    }

    // ---------- 渲染 ----------
    function renderBreadcrumb() {
        const bc = document.getElementById("fsBreadcrumb");
        if (!bc) return;
        let html = `<span class="fs-crumb" data-path="">${escapeHtml(rootName)}</span>`;
        if (currentPath) {
            let acc = "";
            currentPath.split("/").forEach((part) => {
                acc = acc ? `${acc}/${part}` : part;
                html += `<span class="fs-crumb-sep">/</span><span class="fs-crumb" data-path="${escapeHtml(acc)}">${escapeHtml(part)}</span>`;
            });
        }
        bc.innerHTML = html;
        bc.querySelectorAll(".fs-crumb").forEach((el) => {
            el.addEventListener("click", () => navigateTo(el.dataset.path || ""));
        });
    }

    function renderList(entries) {
        const list = document.getElementById("fsFileList");
        if (!list) return;
        if (!entries.length) {
            list.innerHTML = '<div class="fs-empty">该目录为空</div>';
            return;
        }
        list.innerHTML = entries.map((e) => {
            const icon = e.type === "dir" ? "fa-folder" : "fa-file-lines";
            const size = e.type === "dir" ? "—" : formatSize(e.size);
            return `
            <div class="fs-row${e.type === "dir" ? " is-dir" : ""}" data-path="${escapeHtml(e.path)}" data-type="${e.type}" data-name="${escapeHtml(e.name)}">
                <span class="fs-name"><i class="fas ${icon}"></i> ${escapeHtml(e.name)}</span>
                <span class="fs-size">${size}</span>
                <span class="fs-modified">${formatTime(e.modified)}</span>
                <span class="fs-row-actions">
                    <button type="button" class="btn btn-secondary btn-sm fs-rename-btn" title="重命名"><i class="fas fa-pen"></i></button>
                    <button type="button" class="btn btn-danger btn-sm fs-delete-btn" title="删除"><i class="fas fa-trash"></i></button>
                </span>
            </div>`;
        }).join("");

        list.querySelectorAll(".fs-row").forEach((row) => {
            const path = row.dataset.path;
            const type = row.dataset.type;
            const name = row.dataset.name;
            row.querySelector(".fs-name").addEventListener("click", () => {
                if (type === "dir") navigateTo(path);
                else openFile(path);
            });
            row.querySelector(".fs-rename-btn").addEventListener("click", (ev) => {
                ev.stopPropagation();
                renameEntry(path, name);
            });
            row.querySelector(".fs-delete-btn").addEventListener("click", (ev) => {
                ev.stopPropagation();
                deleteEntry(path, name, type === "dir");
            });
        });
    }

    function renderEditorEmpty() {
        document.getElementById("fsEditorName").textContent = "未选择文件";
        document.getElementById("fsEditorMeta").innerHTML = "";
        const ta = document.getElementById("fsEditorContent");
        ta.value = "";
        ta.disabled = false;
        document.getElementById("fsEditorSaveBtn").disabled = true;
        document.getElementById("fsEditorReloadBtn").disabled = true;
        currentFile = null;
        originalContent = "";
        dirty = false;
    }

    function updateMeta(file) {
        const meta = document.getElementById("fsEditorMeta");
        if (!meta || !file) { if (meta) meta.innerHTML = ""; return; }
        const tags = [];
        tags.push(`<span>路径: ${escapeHtml(file.path || "/")}</span>`);
        tags.push(`<span>大小: ${formatSize(file.size)}</span>`);
        tags.push(`<span>修改: ${formatTime(file.modified)}</span>`);
        if (file.encoding === "binary") tags.push('<span class="fs-tag-warn">二进制文件</span>');
        if (file.encoding === "too_large") tags.push('<span class="fs-tag-warn">文件过大</span>');
        if (file.editable) tags.push('<span class="fs-tag-ok">可编辑</span>');
        else if (file.encoding === "text") tags.push('<span class="fs-tag-info">只读</span>');
        meta.innerHTML = tags.join("");
    }

    // ---------- 导航 ----------
    async function navigateTo(relPath) {
        relPath = relPath || "";
        const data = await fetchTree(relPath);
        if (!data.success) {
            showNotification(data.message || "读取目录失败", "error");
            return;
        }
        currentPath = data.path || "";
        renderBreadcrumb();
        renderList(data.entries || []);
    }

    function goUp() {
        if (!currentPath) return;
        navigateTo(parentDir(currentPath));
    }

    async function refresh() {
        await navigateTo(currentPath);
    }

    // ---------- 文件操作 ----------
    async function openFile(path) {
        if (dirty && currentFile && !confirm("当前文件尚未保存，是否放弃修改并打开新文件？")) return;
        const data = await fetchFile(path);
        if (!data.success) {
            showNotification(data.message || "读取文件失败", "error");
            return;
        }
        currentFile = data.file;
        const ta = document.getElementById("fsEditorContent");
        const saveBtn = document.getElementById("fsEditorSaveBtn");
        const reloadBtn = document.getElementById("fsEditorReloadBtn");
        document.getElementById("fsEditorName").textContent = currentFile.name;
        if (currentFile.encoding === "text") {
            ta.value = currentFile.content || "";
            ta.disabled = !currentFile.editable;
            saveBtn.disabled = !currentFile.editable;
            reloadBtn.disabled = false;
        } else {
            ta.value = "";
            ta.disabled = true;
            saveBtn.disabled = true;
            reloadBtn.disabled = true;
        }
        originalContent = ta.value;
        dirty = false;
        updateMeta(currentFile);
    }

    async function saveCurrent() {
        if (!currentFile || !currentFile.editable) return;
        const ta = document.getElementById("fsEditorContent");
        const data = await saveFile(currentFile.path, ta.value);
        if (!data.success) {
            showNotification(data.message || "保存失败", "error");
            return;
        }
        originalContent = ta.value;
        dirty = false;
        document.getElementById("fsEditorSaveBtn").disabled = true;
        showNotification(data.message || "已保存", "success");
        await refresh();
    }

    async function reloadCurrent() {
        if (!currentFile) return;
        if (dirty && !confirm("重新加载将丢弃当前修改，是否继续？")) return;
        await openFile(currentFile.path);
    }

    async function newFolder() {
        const name = prompt("请输入新文件夹名称：");
        if (!name || !name.trim()) return;
        const path = joinPath(currentPath, name.trim());
        const data = await createItem(path, "dir");
        if (!data.success) { showNotification(data.message || "创建失败", "error"); return; }
        showNotification(data.message || "已创建文件夹", "success");
        await refresh();
    }

    async function newFile() {
        const name = prompt("请输入新文件名称：");
        if (!name || !name.trim()) return;
        const path = joinPath(currentPath, name.trim());
        const data = await createItem(path, "file", "");
        if (!data.success) { showNotification(data.message || "创建失败", "error"); return; }
        showNotification(data.message || "已创建文件", "success");
        await refresh();
        await openFile(path);
    }

    async function deleteEntry(path, name, isDir) {
        const tip = isDir ? `文件夹「${name}」及其所有内容` : `文件「${name}」`;
        if (!confirm(`确认删除${tip}？此操作不可恢复。`)) return;
        const data = await deleteItem(path);
        if (!data.success) { showNotification(data.message || "删除失败", "error"); return; }
        showNotification(data.message || "已删除", "success");
        if (currentFile && currentFile.path === path) renderEditorEmpty();
        await refresh();
    }

    async function renameEntry(path, name) {
        const newName = prompt("请输入新名称：", name);
        if (!newName || !newName.trim() || newName.trim() === name) return;
        const newPath = joinPath(parentDir(path), newName.trim());
        const data = await renameItem(path, newPath);
        if (!data.success) { showNotification(data.message || "重命名失败", "error"); return; }
        showNotification(data.message || "已重命名", "success");
        if (currentFile && currentFile.path === path) {
            currentFile.path = newPath;
            currentFile.name = newName.trim();
            document.getElementById("fsEditorName").textContent = currentFile.name;
            updateMeta(currentFile);
        }
        await refresh();
    }

    // ---------- 初始化与加载 ----------
    function init() {
        document.getElementById("fsRefreshBtn")?.addEventListener("click", refresh);
        document.getElementById("fsUpBtn")?.addEventListener("click", goUp);
        document.getElementById("fsNewFolderBtn")?.addEventListener("click", newFolder);
        document.getElementById("fsNewFileBtn")?.addEventListener("click", newFile);
        document.getElementById("fsEditorSaveBtn")?.addEventListener("click", saveCurrent);
        document.getElementById("fsEditorReloadBtn")?.addEventListener("click", reloadCurrent);
        const ta = document.getElementById("fsEditorContent");
        ta?.addEventListener("input", () => {
            dirty = ta.value !== originalContent;
            const saveBtn = document.getElementById("fsEditorSaveBtn");
            if (saveBtn && currentFile && currentFile.editable) {
                saveBtn.disabled = !dirty;
            }
        });
    }

    async function load() {
        if (!rootLoaded) await fetchRoot();
        await navigateTo(currentPath);
    }

    return { init, load };
})();
