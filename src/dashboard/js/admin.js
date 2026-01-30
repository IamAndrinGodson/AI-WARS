// Admin Panel JavaScript

const API_BASE = '/api';

document.addEventListener('DOMContentLoaded', () => {
    loadSystemStatus();
    loadBlockedIPs();
    initAdminControls();

    // Refresh every 10 seconds
    setInterval(() => {
        loadSystemStatus();
        loadBlockedIPs();
    }, 10000);
});

// Load system status
async function loadSystemStatus() {
    try {
        const response = await fetch(`${API_BASE}/admin/system-status`);
        const data = await response.json();

        // Update header status
        const statusEl = document.getElementById('system-status');
        if (data.status === 'healthy') {
            statusEl.innerHTML = '<i class="fas fa-circle"></i> Healthy';
            statusEl.className = 'status-value operational';
        } else {
            statusEl.innerHTML = '<i class="fas fa-circle"></i> Degraded';
            statusEl.className = 'status-value';
            statusEl.style.color = '#f59e0b';
        }

        // Update status grid
        updateStatusValue('status-system', data.status, data.status === 'healthy');
        updateStatusValue('status-anomaly',
            data.models.anomaly_detector.loaded ? 'Loaded' : 'Not Loaded',
            data.models.anomaly_detector.loaded);
        updateStatusValue('status-classifier',
            data.models.threat_classifier.loaded ? 'Loaded' : 'Not Loaded',
            data.models.threat_classifier.loaded);
        updateStatusValue('status-features',
            data.models.feature_engineer.loaded ? 'Loaded' : 'Not Loaded',
            data.models.feature_engineer.loaded);
        updateStatusValue('status-response',
            data.models.response_engine.loaded ? 'Loaded' : 'Not Loaded',
            data.models.response_engine.loaded);

        document.getElementById('status-total-actions').textContent = data.statistics.total_actions;
        document.getElementById('status-blocked-count').textContent = data.statistics.blocked_count;

        // Update config form
        document.getElementById('automation-toggle').checked = data.config.automation_enabled;
        document.getElementById('threshold-input').value = data.config.approval_threshold;

    } catch (error) {
        console.error('Failed to load system status:', error);
    }
}

function updateStatusValue(elementId, text, isOnline) {
    const el = document.getElementById(elementId);
    el.textContent = text;
    el.className = 'value ' + (isOnline ? 'online' : 'offline');
}

// Load blocked IPs
async function loadBlockedIPs() {
    try {
        const response = await fetch(`${API_BASE}/admin/blocked-ips`);
        const blockedIPs = await response.json();

        const container = document.getElementById('blocked-list');

        if (blockedIPs.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-check-circle"></i>
                    <p>No blocked IPs</p>
                </div>
            `;
            return;
        }

        container.innerHTML = blockedIPs.map(item => `
            <div class="blocked-item">
                <div>
                    <span class="ip">${item.ip}</span>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">
                        Blocked: ${new Date(item.blocked_at).toLocaleString()}
                        | Risk: ${item.risk_score?.toFixed(1) || 'N/A'}
                    </div>
                </div>
                <button class="btn-unblock" onclick="unblockIP('${item.ip}')">
                    <i class="fas fa-unlock"></i> Unblock
                </button>
            </div>
        `).join('');

    } catch (error) {
        console.error('Failed to load blocked IPs:', error);
    }
}

// Unblock IP
async function unblockIP(ip) {
    try {
        const response = await fetch(`${API_BASE}/admin/blocked-ips/${ip}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadBlockedIPs();
            alert(`IP ${ip} has been unblocked`);
        }
    } catch (error) {
        console.error('Failed to unblock IP:', error);
    }
}

// Initialize admin controls
function initAdminControls() {
    // Intensity slider
    const intensitySlider = document.getElementById('admin-intensity');
    const intensityValue = document.getElementById('admin-intensity-value');

    intensitySlider.addEventListener('input', (e) => {
        intensityValue.textContent = e.target.value;
    });

    // Save config button
    document.getElementById('save-config-btn').addEventListener('click', saveConfig);

    // Simulate button
    document.getElementById('admin-simulate-btn').addEventListener('click', runAdminSimulation);

    // Clear history button
    document.getElementById('clear-history-btn').addEventListener('click', clearHistory);
}

// Save configuration
async function saveConfig() {
    const automationEnabled = document.getElementById('automation-toggle').checked;
    const threshold = parseInt(document.getElementById('threshold-input').value);

    try {
        const response = await fetch(`${API_BASE}/admin/config?automation_enabled=${automationEnabled}&approval_threshold=${threshold}`, {
            method: 'POST'
        });

        if (response.ok) {
            alert('Configuration saved successfully!');
            loadSystemStatus();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        console.error('Failed to save config:', error);
        alert('Failed to save configuration');
    }
}

// Run simulation from admin panel
async function runAdminSimulation() {
    const attackType = document.getElementById('admin-attack-type').value;
    const intensity = parseInt(document.getElementById('admin-intensity').value);
    const resultDiv = document.getElementById('admin-simulation-result');
    const btn = document.getElementById('admin-simulate-btn');

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
                target_ip: '10.0.0.50'
            })
        });

        const data = await response.json();

        if (response.ok) {
            resultDiv.classList.add('success');
            resultDiv.innerHTML = `
<strong>✓ Simulation Complete</strong>
ID: ${data.simulation_id}
Events: ${data.events_generated}
Anomalies: ${data.summary.anomalies_detected}
Max Risk: ${data.summary.max_risk_score.toFixed(1)}`;

            // Refresh status
            loadSystemStatus();
            loadBlockedIPs();
        } else {
            resultDiv.classList.add('error');
            resultDiv.textContent = `Error: ${data.detail || 'Simulation failed'}`;
        }
    } catch (error) {
        resultDiv.classList.add('error');
        resultDiv.textContent = `Error: ${error.message}`;
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-play"></i> Run Simulation';
}

// Clear history
async function clearHistory() {
    if (!confirm('Are you sure you want to clear all action history?')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/admin/clear-history`, {
            method: 'POST'
        });

        if (response.ok) {
            alert('History cleared successfully!');
            loadSystemStatus();
            loadBlockedIPs();
        }
    } catch (error) {
        console.error('Failed to clear history:', error);
    }
}
