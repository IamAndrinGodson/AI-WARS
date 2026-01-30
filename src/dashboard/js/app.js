// Enhanced Dashboard Application Logic with Real-Time Monitoring

const API_BASE = '/api';
const REFRESH_INTERVAL = 5000; // 5 seconds
const REALTIME_POLL_INTERVAL = 2000; // 2 seconds for real-time updates

// Chart Instances
let distributionChart = null;
let trendChart = null;
let topIpsChart = null;
let portsChart = null;
let actionsChart = null;

// State
let currentMode = 'simulation'; // 'simulation' or 'realtime'
let currentModel = 'synthetic'; // 'synthetic', 'kdd', 'cicids', or 'kmeans'
let realtimePollingId = null;

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initModeToggle();
    initModelToggle();
    initSimulationControls();
    initRealtimeControls();
    updateDashboard();
    setInterval(updateDashboard, REFRESH_INTERVAL);
});

// Initialize mode toggle
function initModeToggle() {
    const simBtn = document.getElementById('mode-simulation');
    const rtBtn = document.getElementById('mode-realtime');

    simBtn.addEventListener('click', () => switchMode('simulation'));
    rtBtn.addEventListener('click', () => switchMode('realtime'));
}

// Initialize Model Toggle
async function initModelToggle() {
    const buttons = {
        'synthetic': document.getElementById('model-synthetic'),
        'kdd': document.getElementById('model-kdd'),
        'cicids': document.getElementById('model-cicids'),
        'kmeans': document.getElementById('model-kmeans')
    };

    // Fetch current state
    try {
        const response = await fetch(`${API_BASE}/config/model`);
        if (response.ok) {
            const data = await response.json();
            currentModel = data.current_model;
            updateModelUI(data.current_model, data.status);
        }
    } catch (e) {
        console.error("Failed to fetch model config", e);
    }

    // Add listeners
    Object.entries(buttons).forEach(([type, btn]) => {
        if (btn) {
            btn.addEventListener('click', () => switchModelType(type));
        }
    });
}

async function switchModelType(type) {
    // Don't switch if already active
    if (type === currentModel) return;

    const btn = document.getElementById(`model-${type}`);
    const originalText = btn ? btn.innerHTML : '';

    try {
        // Show loading state
        if (btn) {
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
            btn.disabled = true;
        }

        const response = await fetch(`${API_BASE}/config/model`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model_type: type })
        });

        if (response.ok) {
            const data = await response.json();
            currentModel = data.current_model;
            updateModelUI(data.current_model);

            // Clear dashboard to reflect new model's perspective
            clearDashboardData();
            await updateDashboard();

            showNotification(`Switched to ${type.toUpperCase()} model`, 'success');
        } else {
            const errorData = await response.json();
            console.error("Failed to switch model:", errorData);
            showNotification(`Failed to switch model: ${errorData.detail || 'Model may not be trained'}`, 'error');
        }
    } catch (e) {
        console.error("Error switching model", e);
        showNotification('Error switching model. Check console for details.', 'error');
    } finally {
        // Restore button state
        if (btn) {
            btn.disabled = false;
        }
        // Re-fetch model state to ensure UI is correct
        try {
            const response = await fetch(`${API_BASE}/config/model`);
            if (response.ok) {
                const data = await response.json();
                updateModelUI(data.current_model, data.status);
            }
        } catch (e) { /* ignore */ }
    }
}

function updateModelUI(activeModel, modelStatus = null) {
    const buttons = {
        'synthetic': document.getElementById('model-synthetic'),
        'kdd': document.getElementById('model-kdd'),
        'cicids': document.getElementById('model-cicids')
    };

    const statusText = document.getElementById('model-status-text');

    const modelNames = {
        'synthetic': 'Synthetic',
        'kdd': 'KDD',
        'cicids': 'CIC-IDS',
        'kmeans': 'K-Means'
    };

    // Reset all buttons
    Object.entries(buttons).forEach(([type, btn]) => {
        if (btn) {
            btn.classList.remove('active');
            // Restore original content
            const icons = {
                'synthetic': 'fa-robot',
                'kdd': 'fa-database',
                'cicids': 'fa-network-wired',
                'kmeans': 'fa-project-diagram'
            };
            btn.innerHTML = `<i class="fas ${icons[type]}"></i> ${modelNames[type]}`;

            // Show loaded/not loaded status if available
            if (modelStatus && modelStatus[type]) {
                if (!modelStatus[type].loaded) {
                    btn.title = 'Model not trained';
                    btn.style.opacity = '0.5';
                } else {
                    btn.title = `Trained on ${modelNames[type]} data`;
                    btn.style.opacity = '1';
                }
            }
        }
    });

    // Activate current
    if (buttons[activeModel]) {
        buttons[activeModel].classList.add('active');
        if (statusText) {
            statusText.textContent = `Active: ${modelNames[activeModel]} Model`;
        }
    }
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
        <span>${message}</span>
    `;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? 'rgba(0, 255, 157, 0.9)' : type === 'error' ? 'rgba(255, 0, 85, 0.9)' : 'rgba(0, 243, 255, 0.9)'};
        color: #000;
        padding: 12px 20px;
        border-radius: 8px;
        font-weight: 600;
        z-index: 10000;
        display: flex;
        align-items: center;
        gap: 10px;
        animation: slideIn 0.3s ease-out;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    `;

    document.body.appendChild(notification);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function clearDashboardData() {
    // Clear trend chart
    if (trendChart) {
        trendChart.data.labels = [];
        trendChart.data.datasets[0].data = [];
        trendChart.update();
    }

    // Clear distribution chart
    if (distributionChart) {
        distributionChart.data.datasets[0].data = [0, 0, 0, 0];
        distributionChart.update();
    }

    // Clear top IPs chart
    if (topIpsChart) {
        topIpsChart.data.labels = [];
        topIpsChart.data.datasets[0].data = [];
        topIpsChart.update();
    }

    // Clear ports chart
    if (portsChart) {
        portsChart.data.labels = [];
        portsChart.data.datasets[0].data = [];
        portsChart.update();
    }

    // Clear actions chart
    if (actionsChart) {
        actionsChart.data.datasets[0].data = [0, 0, 0, 0];
        actionsChart.update();
    }

    // Reset tables
    const feed = document.getElementById('feed-body');
    if (feed) feed.innerHTML = '';

    const rtFeed = document.getElementById('realtime-alert-feed');
    if (rtFeed) {
        rtFeed.innerHTML = '<div class="empty-state"><i class="fas fa-radar"></i><p>Waiting for data...</p></div>';
    }

    // Reset KPIs
    document.getElementById('total-actions').textContent = '0';
    document.getElementById('high-risk-count').textContent = '0';
    document.getElementById('blocked-count').textContent = '0';
    document.getElementById('monitored-count').textContent = '0';
}

// Switch between simulation and real-time mode
function switchMode(mode) {
    currentMode = mode;

    const simBtn = document.getElementById('mode-simulation');
    const rtBtn = document.getElementById('mode-realtime');
    const simPanel = document.getElementById('simulation-panel');
    const rtPanel = document.getElementById('realtime-panel');

    if (mode === 'simulation') {
        simBtn.classList.add('active');
        rtBtn.classList.remove('active');
        simPanel.classList.remove('hidden');
        rtPanel.classList.add('hidden');
        // Stop real-time polling if active
        stopRealtimePolling();
    } else {
        simBtn.classList.remove('active');
        rtBtn.classList.add('active');
        simPanel.classList.add('hidden');
        rtPanel.classList.remove('hidden');
        // Check real-time status
        checkRealtimeStatus();
    }

    // Clear charts and refresh to load mode-specific data
    clearDashboardData();
    updateDashboard();
}

// Initialize Chart.js instances
function initCharts() {
    // Common Chart Options for Dark Theme
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#a3a3a3', font: { family: 'Inter', size: 11 } }
            }
        },
        scales: {
            y: {
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                ticks: { color: '#a3a3a3', font: { family: 'JetBrains Mono', size: 10 } }
            },
            x: {
                grid: { display: false },
                ticks: { color: '#a3a3a3', font: { family: 'JetBrains Mono', size: 10 } }
            }
        }
    };

    // Threat Distribution Chart (Doughnut)
    const distCtx = document.getElementById('threatDistributionChart').getContext('2d');
    distributionChart = new Chart(distCtx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 255, 157, 0.2)',  // Neon Green
                    'rgba(0, 243, 255, 0.2)',  // Neon Blue/Cyan
                    'rgba(255, 189, 0, 0.2)',  // Neon Yellow
                    'rgba(128, 0, 255, 0.2)'    // Neon Violet
                ],
                borderColor: [
                    '#00ff9d',
                    '#00f3ff',
                    '#ffbd00',
                    '#8000ff'
                ],
                borderWidth: 1,
                hoverOffset: 4
            }]
        },
        options: {
            ...commonOptions,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#a3a3a3', padding: 20, font: { size: 11 } }
                }
            },
            scales: {} // No scales for doughnut
        }
    });

    // Anomaly Trend Chart (Line)
    const trendCtx = document.getElementById('anomalyTrendChart').getContext('2d');
    trendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Risk Score',
                data: [],
                borderColor: '#00f3ff',
                backgroundColor: 'rgba(0, 243, 255, 0.1)',
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#000',
                pointBorderColor: '#00f3ff',
                pointBorderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 6
            }]
        },
        options: {
            ...commonOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#a3a3a3' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#a3a3a3', maxRotation: 45 }
                }
            },
            plugins: { legend: { display: false } }
        }
    });

    // Top IPs Chart (Horizontal Bar)
    const ipsCtx = document.getElementById('topIpsChart').getContext('2d');
    topIpsChart = new Chart(ipsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Threats',
                data: [],
                backgroundColor: 'rgba(188, 19, 254, 0.2)', // Neon Purple
                borderColor: '#bc13fe',
                borderWidth: 1,
                borderRadius: 4,
                barThickness: 20
            }]
        },
        options: {
            ...commonOptions,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#a3a3a3' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#a3a3a3', font: { family: 'JetBrains Mono', size: 10 } }
                }
            },
            plugins: { legend: { display: false } }
        }
    });

    // Ports Chart (Bar)
    const portsCtx = document.getElementById('portsChart').getContext('2d');
    portsChart = new Chart(portsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Connections',
                data: [],
                backgroundColor: 'rgba(255, 189, 0, 0.2)', // Neon Yellow
                borderColor: '#ffbd00',
                borderWidth: 1,
                borderRadius: 4,
                barThickness: 30
            }]
        },
        options: {
            ...commonOptions,
            plugins: { legend: { display: false } }
        }
    });

    // Actions Distribution Chart (Doughnut)
    const actionsCtx = document.getElementById('actionsChart').getContext('2d');
    actionsChart = new Chart(actionsCtx, {
        type: 'doughnut',
        data: {
            labels: ['Monitor', 'Alert', 'Isolate', 'Block'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 255, 157, 0.2)',
                    'rgba(0, 243, 255, 0.2)',
                    'rgba(255, 189, 0, 0.2)',
                    'rgba(255, 0, 85, 0.2)'
                ],
                borderColor: [
                    '#00ff9d',
                    '#00f3ff',
                    '#ffbd00',
                    '#8000ff'
                ],
                borderWidth: 1
            }]
        },
        options: {
            ...commonOptions,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#a3a3a3', padding: 15, usePointStyle: true }
                }
            },
            scales: {}
        }
    });
}

// Initialize simulation controls
function initSimulationControls() {
    const intensitySlider = document.getElementById('attack-intensity');
    const intensityValue = document.getElementById('intensity-value');
    const simulateBtn = document.getElementById('simulate-btn');

    if (intensitySlider) {
        intensitySlider.addEventListener('input', (e) => {
            intensityValue.textContent = e.target.value;
        });
    }

    if (simulateBtn) {
        simulateBtn.addEventListener('click', runSimulation);
    }
}

// Initialize real-time monitoring controls
function initRealtimeControls() {
    const startBtn = document.getElementById('rt-start-btn');
    const stopBtn = document.getElementById('rt-stop-btn');

    startBtn.addEventListener('click', startRealtimeMonitoring);
    stopBtn.addEventListener('click', stopRealtimeMonitoring);
}

// Check real-time monitoring status
async function checkRealtimeStatus() {
    try {
        const response = await fetch(`${API_BASE}/realtime/status`);
        const data = await response.json();
        updateRealtimeUI(data);

        if (data.running) {
            startRealtimePolling();
        }
    } catch (e) {
        console.error("Failed to check real-time status", e);
    }
}

// Start real-time monitoring
async function startRealtimeMonitoring() {
    const startBtn = document.getElementById('rt-start-btn');
    startBtn.disabled = true;
    startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

    try {
        const response = await fetch(`${API_BASE}/realtime/start`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.status === 'started' || data.status === 'already_running') {
            updateRealtimeUI({ running: true });
            startRealtimePolling();
        }
    } catch (e) {
        console.error("Failed to start monitoring", e);
    }

    startBtn.disabled = false;
    startBtn.innerHTML = '<i class="fas fa-play"></i> Start Monitoring';
}

// Stop real-time monitoring
async function stopRealtimeMonitoring() {
    try {
        const response = await fetch(`${API_BASE}/realtime/stop`, {
            method: 'POST'
        });
        const data = await response.json();

        updateRealtimeUI({ running: false, stats: data.stats });
        stopRealtimePolling();
    } catch (e) {
        console.error("Failed to stop monitoring", e);
    }
}

// Start polling for real-time updates
function startRealtimePolling() {
    if (realtimePollingId) return;

    realtimePollingId = setInterval(async () => {
        await pollRealtimeData();
    }, REALTIME_POLL_INTERVAL);

    // Initial poll
    pollRealtimeData();
}

// Stop polling
function stopRealtimePolling() {
    if (realtimePollingId) {
        clearInterval(realtimePollingId);
        realtimePollingId = null;
    }
}

// Poll real-time data
async function pollRealtimeData() {
    try {
        // Get status and stats
        const statusResponse = await fetch(`${API_BASE}/realtime/status`);
        const status = await statusResponse.json();

        // Get alerts
        const alertsResponse = await fetch(`${API_BASE}/realtime/alerts?limit=20`);
        const alerts = await alertsResponse.json();

        updateRealtimeUI(status);
        updateRealtimeAlerts(alerts);

        // Also update the main dashboard
        await updateDashboard();

    } catch (e) {
        console.error("Failed to poll real-time data", e);
    }
}

// Update real-time UI elements
function updateRealtimeUI(data) {
    const statusBadge = document.getElementById('realtime-status-badge');
    const startBtn = document.getElementById('rt-start-btn');
    const stopBtn = document.getElementById('rt-stop-btn');

    if (data.running) {
        statusBadge.textContent = 'Running';
        statusBadge.className = 'realtime-badge online';
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        statusBadge.textContent = 'Stopped';
        statusBadge.className = 'realtime-badge offline';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }

    // Update stats
    if (data.stats) {
        document.getElementById('rt-connections').textContent = data.stats.total_connections_seen || 0;
        document.getElementById('rt-events').textContent = data.stats.events_processed || 0;
        document.getElementById('rt-alerts').textContent = data.stats.alerts_generated || 0;
    }
}

// Update real-time alerts feed
function updateRealtimeAlerts(alerts) {
    const feed = document.getElementById('realtime-alert-feed');

    if (!alerts || alerts.length === 0) {
        feed.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-check-circle"></i>
                <p>No alerts detected</p>
            </div>
        `;
        return;
    }

    feed.innerHTML = alerts.map(alert => `
        <div class="realtime-alert-item ${alert.severity}">
            <div>
                <strong>${alert.threat_id}</strong>
                <span style="margin-left: 10px; color: #94a3b8;">
                    ${alert.src_ip} → ${alert.dst_ip}:${alert.dst_port}
                </span>
            </div>
            <div>
                <span class="badge-severity ${alert.severity}">${alert.severity}</span>
                <span style="margin-left: 10px;">${(alert.risk_score || 0).toFixed(1)}</span>
            </div>
        </div>
    `).join('');
}

// Run attack simulation
async function runSimulation() {
    const attackType = document.getElementById('attack-type').value;
    const intensity = parseInt(document.getElementById('attack-intensity').value);
    const targetIp = document.getElementById('target-ip').value;
    const resultDiv = document.getElementById('simulation-result');
    const btn = document.getElementById('simulate-btn');

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Simulating...';
    resultDiv.classList.remove('hidden', 'success', 'error');
    resultDiv.textContent = 'Running simulation...';
    resultDiv.classList.remove('hidden');

    try {
        const response = await fetch(`${API_BASE}/simulate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                attack_type: attackType,
                intensity: intensity,
                duration_seconds: 10,
                target_ip: targetIp
            })
        });

        const data = await response.json();

        if (response.ok) {
            resultDiv.classList.add('success');
            resultDiv.innerHTML = `
<strong>✓ Simulation Complete: ${data.simulation_id}</strong>
Attack Type: ${attackType.toUpperCase()}
Events Generated: ${data.events_generated}
Anomalies Detected: ${data.summary.anomalies_detected}
Avg Risk Score: ${data.summary.avg_risk_score.toFixed(1)}
Max Risk Score: ${data.summary.max_risk_score.toFixed(1)}

Severity Breakdown:
  Critical: ${data.summary.threats_by_severity.critical}
  High: ${data.summary.threats_by_severity.high}
  Medium: ${data.summary.threats_by_severity.medium}
  Low: ${data.summary.threats_by_severity.low}`;

            // Immediately refresh dashboard
            await updateDashboard();
        } else {
            resultDiv.classList.add('error');
            resultDiv.textContent = `Error: ${data.detail || 'Simulation failed'}`;
        }
    } catch (error) {
        resultDiv.classList.add('error');
        resultDiv.textContent = `Error: ${error.message}`;
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-play"></i> Launch Simulation';
}

// Fetch and update all dashboard data
async function updateDashboard() {
    try {
        await Promise.all([
            fetchStats(),
            fetchDetailedStats(),
            fetchDetailedHistory()
        ]);
        updateLastUpdated();
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}

// Fetch System Stats and update KPIs
async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/stats?source=${currentMode}`);
        const data = await response.json();
        updateKPIs(data);
    } catch (e) {
        console.error("Error fetching stats:", e);
    }
}

// Update KPI cards with stats data
function updateKPIs(data) {
    if (!data) return;

    const totalActions = document.getElementById('total-actions');
    const highRisk = document.getElementById('high-risk-count');
    const blocked = document.getElementById('blocked-count');
    const monitored = document.getElementById('monitored-count');

    if (totalActions) totalActions.textContent = data.total_actions || 0;
    if (highRisk) highRisk.textContent = data.high_risk_threats || 0;
    if (blocked) blocked.textContent = data.blocked_ips || 0;
    if (monitored) monitored.textContent = data.monitored_flows || 0;
}

// Fetch Detailed Stats for charts
async function fetchDetailedStats() {
    try {
        const response = await fetch(`${API_BASE}/stats/detailed?source=${currentMode}`);
        const data = await response.json();
        updateCharts(data);
    } catch (e) {
        console.error("Failed to fetch detailed stats", e);
    }
}

// Update charts with detailed stats
function updateCharts(data) {
    if (!data) return;

    // Update Severity Distribution Chart
    if (distributionChart && data.severity_distribution) {
        const dist = data.severity_distribution;
        distributionChart.data.datasets[0].data = [
            dist.low || 0,
            dist.medium || 0,
            dist.high || 0,
            dist.critical || 0
        ];
        distributionChart.update();
    }

    // Update Top Source IPs Chart
    if (topIpsChart && data.top_source_ips) {
        const topIps = data.top_source_ips.slice(0, 5);
        topIpsChart.data.labels = topIps.map(item => item.ip);
        topIpsChart.data.datasets[0].data = topIps.map(item => item.count);
        topIpsChart.update();
    }

    // Update Ports Chart
    if (portsChart && data.top_destination_ports) {
        const topPorts = data.top_destination_ports.slice(0, 6);
        portsChart.data.labels = topPorts.map(item => `Port ${item.port}`);
        portsChart.data.datasets[0].data = topPorts.map(item => item.count);
        portsChart.update();
    }
}

// Fetch Detailed History for trend chart and feed
async function fetchDetailedHistory() {
    try {
        const response = await fetch(`${API_BASE}/history/detailed?limit=50&source=${currentMode}`);
        if (!response.ok) return;

        const history = await response.json();

        updateTrendChart(history);
        updateActionsChart(history);
        updateFeed(history);
    } catch (e) {
        console.error("Failed to fetch detailed history", e);
    }
}

// Update Trend Chart
function updateTrendChart(history) {
    if (!trendChart || !history || history.length === 0) return;

    const reversedHistory = [...history].reverse().slice(-20);

    trendChart.data.labels = reversedHistory.map(h =>
        new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    );
    trendChart.data.datasets[0].data = reversedHistory.map(h => h.risk_score || 0);
    trendChart.update();
}

// Update Actions Chart
function updateActionsChart(history) {
    if (!actionsChart || !history) return;

    const actionCounts = {
        monitor: 0,
        alert: 0,
        isolate: 0,
        block: 0
    };

    history.forEach(h => {
        const action = (h.action || 'monitor').toLowerCase();
        if (actionCounts.hasOwnProperty(action)) {
            actionCounts[action]++;
        }
    });

    actionsChart.data.datasets[0].data = [
        actionCounts.monitor,
        actionCounts.alert,
        actionCounts.isolate,
        actionCounts.block
    ];
    actionsChart.update();
}

// Update Live Feed Table
function updateFeed(history) {
    const tbody = document.getElementById('feed-body');
    if (!tbody || !history) return;

    tbody.innerHTML = '';

    history.forEach(item => {
        const tr = document.createElement('tr');

        const time = new Date(item.timestamp).toLocaleTimeString();
        const severityClass = (item.severity || 'low').toLowerCase();
        const actionClass = (item.action || 'monitor').toLowerCase();

        // Highlight real-time events
        const isRealtime = item.threat_id && item.threat_id.startsWith('RT-');
        const rowStyle = isRealtime ? 'background: rgba(16, 185, 129, 0.05);' : '';

        // Enriched Data
        const serviceTag = item.service ? `<span class="service-tag" title="${item.service_desc || ''}">${item.service}</span>` : '';
        const processName = item.process && item.process !== 'unknown' ? item.process : '<span style="opacity:0.3">-</span>';

        tr.style.cssText = rowStyle;
        tr.innerHTML = `
            <td>${time} ${isRealtime ? '<i class="fas fa-broadcast-tower" style="color: #10b981; margin-left: 4px;" title="Real-Time"></i>' : ''}</td>
            <td style="font-family:monospace">${item.threat_id || 'N/A'}</td>
            <td class="ip-cell" data-ip="${item.src_ip}">
                ${item.src_ip || 'N/A'}
                <div class="ip-tooltip">Loading info...</div>
            </td>
            <td class="ip-cell" data-ip="${item.dst_ip}">
                ${item.dst_ip || 'N/A'}
                <div class="ip-tooltip">Loading info...</div>
            </td>
            <td class="port-cell">${item.dst_port || 'N/A'}${serviceTag}</td>
            <td class="process-cell">${processName}</td>
            <td><span class="badge-severity ${severityClass}">${item.severity || 'low'}</span></td>
            <td><span class="badge-action ${actionClass}">${item.action || 'monitor'}</span></td>
            <td>${(item.risk_score || 0).toFixed(1)}</td>
        `;

        // Add hover listeners for enrichment
        const ipCells = tr.querySelectorAll('.ip-cell');
        ipCells.forEach(cell => {
            cell.addEventListener('mouseenter', () => fetchIpEnrichment(cell));
        });

        tbody.appendChild(tr);
    });
}

// Cache for IP enrichment to avoid repeated API calls
const ipCache = {};

async function fetchIpEnrichment(cell) {
    const ip = cell.getAttribute('data-ip');
    const tooltip = cell.querySelector('.ip-tooltip');

    if (!ip || ip === 'N/A') {
        tooltip.style.display = 'none';
        return;
    }

    // Check cache
    if (ipCache[ip]) {
        renderTooltip(tooltip, ipCache[ip]);
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/enrich/ip/${ip}`);
        if (response.ok) {
            const data = await response.json();
            ipCache[ip] = data; // Cache it
            renderTooltip(tooltip, data);
        } else {
            tooltip.textContent = "Info unavailable";
        }
    } catch (e) {
        console.error("Failed to enrich IP", e);
        tooltip.textContent = "Lookup failed";
    }
}

function renderTooltip(tooltip, data) {
    tooltip.innerHTML = `
        <div class="tooltip-row">
            <span class="tooltip-label">Type:</span>
            <span class="tooltip-val" style="text-transform: capitalize">${data.type}</span>
        </div>
        <div class="tooltip-row">
            <span class="tooltip-label">Host:</span>
            <span class="tooltip-val">${data.hostname || 'N/A'}</span>
        </div>
        <div class="tooltip-row">
            <span class="tooltip-label">Loc:</span>
            <span class="tooltip-val">${data.location}</span>
        </div>
    `;
}

function updateLastUpdated() {
    const now = new Date();
    document.getElementById('last-updated').textContent = now.toLocaleTimeString();
}
