/**
 * Smart Airport Security System - Frontend Application
 * Handles WebSocket connections, API calls, and UI updates
 */

// ─── Configuration ──────────────────────────────────────
const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/ws`;

// ─── State ──────────────────────────────────────────────
let ws = null;
let wsReconnectTimer = null;
let statsTimer = null;
let currentSection = 'dashboard';

// ─── Initialize ─────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initWebSocket();
    updateDateTime();
    setInterval(updateDateTime, 1000);
    fetchStats();
    statsTimer = setInterval(fetchStats, 3000);
    fetchCriminals();
    fetchAlerts();
});

// ─── Navigation ─────────────────────────────────────────
function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const section = btn.dataset.section;
            switchSection(section);
        });
    });
}

function switchSection(section) {
    currentSection = section;
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`[data-section="${section}"]`).classList.add('active');
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    document.getElementById(`section-${section}`).classList.add('active');

    const titles = {
        dashboard: ['Security Command Center', 'Real-time Surveillance Dashboard'],
        alerts: ['Alert Management', 'View and manage security alerts'],
        database: ['Criminal Watchlist', 'Manage criminal database records'],
        logs: ['Detection Logs', 'View all detection history'],
        settings: ['System Settings', 'Configure cameras and system parameters']
    };
    document.getElementById('page-title').textContent = titles[section]?.[0] || '';
    document.getElementById('page-subtitle').textContent = titles[section]?.[1] || '';

    if (section === 'alerts') refreshAlerts();
    if (section === 'database') fetchCriminals();
    if (section === 'logs') refreshLogs();
    if (section === 'settings') fetchCameraList();
}

// ─── WebSocket ──────────────────────────────────────────
function initWebSocket() {
    try {
        ws = new WebSocket(WS_URL);
        ws.onopen = () => {
            console.log('WebSocket connected');
            document.getElementById('system-status').querySelector('.status-dot').classList.add('active');
        };
        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === 'alert') handleNewAlert(msg.data);
            if (msg.type === 'stats') updateStatsUI(msg.data);
        };
        ws.onclose = () => {
            console.log('WebSocket disconnected, reconnecting...');
            document.getElementById('system-status').querySelector('.status-dot').classList.remove('active');
            wsReconnectTimer = setTimeout(initWebSocket, 3000);
        };
        ws.onerror = () => ws.close();
    } catch (e) {
        console.error('WebSocket error:', e);
        wsReconnectTimer = setTimeout(initWebSocket, 5000);
    }
}

// ─── Alert Handling ─────────────────────────────────────
function handleNewAlert(alert) {
    addAlertToPanel(alert);
    updateAlertBadge();
    try { document.getElementById('alert-sound').play().catch(() => {}); } catch(e) {}
}

function addAlertToPanel(alert) {
    const list = document.getElementById('alerts-list');
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();

    const typeClass = alert.threat_level === 'Criminal' ? 'criminal'
                    : alert.threat_level === 'Suspicious' ? 'suspicious' : 'behavior';
    const threatClass = alert.threat_level === 'Criminal' ? 'threat-criminal'
                      : alert.threat_level === 'Suspicious' ? 'threat-suspicious' : 'threat-safe';

    const time = formatTime(alert.timestamp);
    const el = document.createElement('div');
    el.className = `alert-item ${typeClass}`;
    el.id = `alert-${alert.id}`;
    el.innerHTML = `
        <div class="alert-top">
            <span class="alert-threat ${threatClass}">${alert.threat_level}</span>
            <span class="alert-time">${time}</span>
        </div>
        <div class="alert-name">${escapeHtml(alert.person_name)}</div>
        <div class="alert-detail">
            <span>📷 ${escapeHtml(alert.camera_id)}</span>
            <span>📍 ${escapeHtml(alert.camera_location)}</span>
            ${alert.confidence ? `<span>🎯 ${alert.confidence}%</span>` : ''}
        </div>
    `;
    el.onclick = () => acknowledgeAlert(alert.id);
    list.insertBefore(el, list.firstChild);

    // Keep only last 50 alerts in panel
    while (list.children.length > 50) list.removeChild(list.lastChild);
}

async function acknowledgeAlert(alertId) {
    try {
        await fetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
        const el = document.getElementById(`alert-${alertId}`);
        if (el) {
            el.style.opacity = '0.4';
            el.style.borderLeftColor = 'var(--text-muted)';
        }
        updateAlertBadge();
    } catch (e) { console.error('Acknowledge error:', e); }
}

function updateAlertBadge() {
    fetch(`${API_BASE}/api/alerts/unacknowledged`)
        .then(r => r.json())
        .then(data => {
            const count = Array.isArray(data) ? data.length : 0;
            document.getElementById('alert-badge').textContent = count;
            document.getElementById('alerts-pill-value').textContent = count;
            document.getElementById('alert-badge').style.display = count > 0 ? 'inline' : 'none';
        })
        .catch(() => {});
}

async function refreshAlerts() {
    try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=100`);
        const alerts = await res.json();
        const tbody = document.getElementById('alerts-tbody');
        tbody.innerHTML = '';
        alerts.forEach(a => {
            const threatClass = a.threat_level === 'Criminal' ? 'threat-criminal'
                              : a.threat_level === 'Suspicious' ? 'threat-suspicious' : 'threat-safe';
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:0.78rem">${formatTime(a.timestamp)}</td>
                <td>${escapeHtml(a.alert_type.replace(/_/g, ' '))}</td>
                <td><span class="threat-tag ${threatClass}">${a.threat_level}</span></td>
                <td>${escapeHtml(a.person_name)}</td>
                <td>${a.confidence ? a.confidence + '%' : '-'}</td>
                <td>${escapeHtml(a.camera_id)}</td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(a.details)}</td>
                <td>${a.acknowledged
                    ? '<span style="color:var(--accent-green)">✓ Ack</span>'
                    : `<button class="btn-sm" onclick="acknowledgeAlert('${a.id}')">Acknowledge</button>`
                }</td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) { console.error('Fetch alerts error:', e); }
}

async function clearAlerts() {
    if (!confirm('Clear all alerts?')) return;
    try {
        await fetch(`${API_BASE}/api/alerts`, { method: 'DELETE' });
        document.getElementById('alerts-list').innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <p>No alerts detected</p><span>System monitoring active</span>
            </div>`;
        document.getElementById('alerts-tbody').innerHTML = '';
        updateAlertBadge();
    } catch (e) { console.error('Clear alerts error:', e); }
}

// ─── Stats ──────────────────────────────────────────────
async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/api/stats`);
        const stats = await res.json();
        updateStatsUI(stats);
    } catch (e) { /* server may not be ready */ }
}

function updateStatsUI(stats) {
    document.getElementById('stat-total-cameras').textContent = stats.active_cameras || 0;
    document.getElementById('stat-total-detections').textContent = stats.total_detections || 0;
    document.getElementById('stat-total-alerts').textContent = stats.unacknowledged_alerts || 0;
    document.getElementById('stat-db-count').textContent = stats.criminals_in_db || 0;
    document.getElementById('fps-value').textContent = stats.fps || 0;
    document.getElementById('cameras-value').textContent = stats.active_cameras || 0;

    // Settings page
    const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    el('info-uptime', formatUptime(stats.uptime_seconds || 0));
    el('info-detections', stats.total_detections || 0);
    el('info-fps', (stats.fps || 0) + ' fps');
    el('info-cameras', stats.active_cameras || 0);
    el('info-watchlist', stats.criminals_in_db || 0);
}

// ─── Criminal Database ──────────────────────────────────
async function fetchCriminals() {
    try {
        const res = await fetch(`${API_BASE}/api/criminals`);
        const criminals = await res.json();
        renderCriminals(criminals);
    } catch (e) { console.error('Fetch criminals error:', e); }
}

function renderCriminals(criminals) {
    const grid = document.getElementById('criminals-grid');
    if (!criminals.length) {
        grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;padding:60px">
            <p>No criminals in watchlist</p><span>Add records using the button above</span></div>`;
        return;
    }
    grid.innerHTML = criminals.map(c => {
        const badgeClass = c.status === 'Wanted' ? 'badge-wanted'
                         : c.status === 'Arrested' ? 'badge-arrested' : 'badge-investigation';
        const dangerColor = c.danger_level === 'Critical' ? 'var(--accent-red)'
                          : c.danger_level === 'High' ? 'var(--accent-orange)'
                          : c.danger_level === 'Medium' ? 'var(--accent-yellow)' : 'var(--accent-green)';
        return `
        <div class="criminal-card" id="criminal-${c.id}">
            <div class="criminal-card-header">
                <div>
                    <div class="criminal-name">${escapeHtml(c.name)}</div>
                    <div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px">ID: ${c.id || '-'}</div>
                </div>
                <span class="criminal-badge ${badgeClass}">${escapeHtml(c.status)}</span>
            </div>
            <div class="criminal-card-body">
                <div class="criminal-info-row"><span class="label">Crime</span><span class="value">${escapeHtml(c.crime)}</span></div>
                <div class="criminal-info-row"><span class="label">Case ID</span><span class="value" style="font-family:var(--font-mono)">${escapeHtml(c.case_id)}</span></div>
                <div class="criminal-info-row"><span class="label">Danger</span><span class="value" style="color:${dangerColor}">${escapeHtml(c.danger_level || 'High')}</span></div>
                <div class="criminal-info-row"><span class="label">Images</span><span class="value">${(c.images || []).length} files</span></div>
                ${c.last_seen ? `<div class="criminal-info-row"><span class="label">Last Seen</span><span class="value" style="font-size:0.75rem">${escapeHtml(c.last_seen)}</span></div>` : ''}
                ${c.description ? `<div style="margin-top:8px;font-size:0.78rem;color:var(--text-secondary)">${escapeHtml(c.description)}</div>` : ''}
            </div>
            <div class="criminal-card-footer">
                <button class="btn-sm" onclick="removeCriminal('${c.id}')" style="color:var(--accent-red);border-color:rgba(255,51,102,0.3)">Remove</button>
            </div>
        </div>`;
    }).join('');
}

function toggleAddForm() {
    const panel = document.getElementById('add-form-panel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}

async function addCriminal(event) {
    event.preventDefault();
    const form = document.getElementById('add-criminal-form');
    const formData = new FormData(form);

    try {
        const res = await fetch(`${API_BASE}/api/criminals`, {
            method: 'POST',
            body: formData
        });
        if (res.ok) {
            form.reset();
            toggleAddForm();
            fetchCriminals();
            fetchStats();
        } else {
            const err = await res.json();
            alert('Error: ' + (err.detail || err.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Error adding criminal: ' + e.message);
    }
}

async function removeCriminal(id) {
    if (!confirm('Remove this criminal from the watchlist?')) return;
    try {
        await fetch(`${API_BASE}/api/criminals/${id}`, { method: 'DELETE' });
        fetchCriminals();
        fetchStats();
    } catch (e) { alert('Error removing: ' + e.message); }
}

// ─── Logs ───────────────────────────────────────────────
async function refreshLogs() {
    try {
        const res = await fetch(`${API_BASE}/api/logs?limit=200`);
        const logs = await res.json();
        const tbody = document.getElementById('logs-tbody');
        tbody.innerHTML = '';
        logs.forEach(log => {
            const threat = log.threat || 'Safe';
            const threatClass = threat === 'Criminal' ? 'threat-criminal'
                              : threat === 'Suspicious' ? 'threat-suspicious' : 'threat-safe';
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:0.78rem">${formatTime(log.timestamp)}</td>
                <td>${escapeHtml(log.person || '-')}</td>
                <td><span class="threat-tag ${threatClass}">${threat}</span></td>
                <td>${log.confidence ? log.confidence + '%' : '-'}</td>
                <td>${escapeHtml(log.camera || '-')}</td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) { console.error('Fetch logs error:', e); }
}

// ─── Camera Management ──────────────────────────────────
async function fetchCameraList() {
    try {
        const res = await fetch(`${API_BASE}/api/cameras`);
        const cameras = await res.json();
        const list = document.getElementById('camera-list');
        list.innerHTML = cameras.map(c => `
            <div class="camera-item">
                <div class="cam-info">
                    <span class="status-dot ${c.status === 'active' ? 'active' : ''}"></span>
                    <strong>${escapeHtml(c.camera_id)}</strong>
                    <span style="color:var(--text-muted)">${escapeHtml(c.location)}</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px">
                    <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--accent-cyan)">${c.fps} fps</span>
                    <button class="btn-sm" onclick="removeCamera('${c.camera_id}')" style="color:var(--accent-red)">×</button>
                </div>
            </div>
        `).join('');
    } catch (e) { console.error('Fetch cameras error:', e); }
}

async function addCamera(event) {
    event.preventDefault();
    const formData = new FormData();
    formData.append('camera_id', document.getElementById('cam-id').value);
    formData.append('source', document.getElementById('cam-source').value);
    formData.append('location', document.getElementById('cam-location').value);
    try {
        await fetch(`${API_BASE}/api/cameras`, { method: 'POST', body: formData });
        document.getElementById('add-camera-form').reset();
        fetchCameraList();
        fetchStats();
    } catch (e) { alert('Error adding camera: ' + e.message); }
}

async function removeCamera(id) {
    if (!confirm(`Remove camera ${id}?`)) return;
    try {
        await fetch(`${API_BASE}/api/cameras/${id}`, { method: 'DELETE' });
        fetchCameraList();
        fetchStats();
    } catch (e) { alert('Error: ' + e.message); }
}

// ─── Utilities ──────────────────────────────────────────
function updateDateTime() {
    const now = new Date();
    const opts = { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
    document.getElementById('datetime-display').textContent = now.toLocaleDateString('en-US', opts);
}

function formatTime(isoStr) {
    if (!isoStr) return '--';
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch { return isoStr; }
}

function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h}h ${m}m ${s}s`;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
