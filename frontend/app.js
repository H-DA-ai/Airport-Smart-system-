/**
 * Smart Airport Security System v3.0 — Frontend
 * Binary detection: CRIMINAL (alert + evidence + police) | SAFE (blurred)
 */

const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/ws`;

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
    statsTimer = setInterval(fetchStats, 2000);
    fetchCriminals();
    fetchAlerts();
});

// ─── Navigation ─────────────────────────────────────────
function initNavigation() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => switchSection(btn.dataset.section));
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
        alerts:    ['Alert History', 'All criminal detection alerts'],
        police:    ['Police Dispatch Log', 'All police dispatch records'],
        database:  ['Criminal Watchlist', 'Manage criminal database records'],
        logs:      ['Detection Logs', 'Full detection history'],
        settings:  ['System Settings', 'Configure cameras and system']
    };
    document.getElementById('page-title').textContent = titles[section]?.[0] || '';
    document.getElementById('page-subtitle').textContent = titles[section]?.[1] || '';

    if (section === 'alerts') refreshAlerts();
    if (section === 'police') refreshPoliceLog();
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
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'alert') handleNewAlert(msg.data);
                if (msg.type === 'stats') updateStatsUI(msg.data);
                if (msg.type === 'police_alert') handlePoliceAlert(msg.data);
                if (msg.type === 'pong') {} // heartbeat
            } catch(e) {}
        };
        ws.onclose = () => {
            document.getElementById('system-status').querySelector('.status-dot').classList.remove('active');
            wsReconnectTimer = setTimeout(initWebSocket, 3000);
        };
        ws.onerror = () => ws.close();
    } catch (e) {
        wsReconnectTimer = setTimeout(initWebSocket, 5000);
    }
}

// ─── Alert Handling ─────────────────────────────────────
function handleNewAlert(alert) {
    addAlertToPanel(alert);
    updateAlertBadge();
    // Flash the video panel red
    flashCriminalWarning();
    try { document.getElementById('alert-sound').play().catch(() => {}); } catch(e) {}
}

function handlePoliceAlert(dispatch) {
    showPoliceOverlay(dispatch);
}

function flashCriminalWarning() {
    const videoPanel = document.querySelector('.video-panel');
    if (videoPanel) {
        videoPanel.classList.add('criminal-flash');
        setTimeout(() => videoPanel.classList.remove('criminal-flash'), 2000);
    }
}

function showPoliceOverlay(dispatch) {
    const overlay = document.getElementById('police-overlay');
    const nameEl = document.getElementById('police-overlay-name');
    const locEl = document.getElementById('police-overlay-location');

    nameEl.textContent = dispatch.criminal_name || 'Unknown Criminal';
    locEl.textContent = `📍 ${dispatch.camera_location || ''} — ${dispatch.camera_id || ''}`;

    overlay.classList.add('active');
    setTimeout(() => overlay.classList.remove('active'), 4500);
}

function addAlertToPanel(alert) {
    const list = document.getElementById('alerts-list');
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();

    const time = formatTime(alert.timestamp);
    const policeTag = alert.police_alerted
        ? `<span class="police-dispatched-tag">🚔 Police Notified</span>` : '';

    const el = document.createElement('div');
    el.className = 'alert-item criminal';
    el.id = `alert-panel-${alert.id}`;
    el.innerHTML = `
        <div class="alert-top">
            <span class="alert-threat threat-criminal">⚠ CRIMINAL</span>
            <span class="alert-time">${time}</span>
        </div>
        <div class="alert-name">${escapeHtml(alert.person_name?.replace('CONFIRMED: ', '') || 'Unknown')}</div>
        <div class="alert-detail">
            <span>📷 ${escapeHtml(alert.camera_id || '')}</span>
            <span>📍 ${escapeHtml(alert.camera_location || '')}</span>
            ${alert.confidence ? `<span>🎯 ${alert.confidence}%</span>` : ''}
        </div>
        <div class="alert-actions" id="panel-actions-${alert.id}">
            <button class="evidence-btn" onclick="showEvidence('${alert.id}')">📷 Evidence</button>
            ${policeTag}
        </div>
        <div id="panel-thumb-${alert.id}"></div>
    `;
    list.insertBefore(el, list.firstChild);

    // Async-load evidence thumbnail into panel card
    if (alert.has_evidence) {
        fetch(`${API_BASE}/api/alerts/${alert.id}/evidence`)
            .then(r => r.json())
            .then(data => {
                const imgs = data.evidence_images || [];
                const container = document.getElementById(`panel-thumb-${alert.id}`);
                if (container && imgs.length) {
                    container.innerHTML = imgs.map(b64 =>
                        `<img src="data:image/jpeg;base64,${b64}"
                             class="evidence-panel-thumb"
                             onclick="showEvidence('${alert.id}')"
                             title="Click to view full evidence">`
                    ).join('');
                }
            })
            .catch(() => {});
    }

    // Keep only last 30 in panel
    while (list.children.length > 30) list.removeChild(list.lastChild);
}

async function showEvidence(alertId) {
    try {
        const res = await fetch(`${API_BASE}/api/alerts/${alertId}/evidence`);
        const data = await res.json();
        const images = data.evidence_images || [];

        const modal = document.getElementById('evidence-modal');
        const body = document.getElementById('evidence-modal-body');
        document.getElementById('evidence-modal-title').textContent = `Evidence — Alert ${alertId}`;

        if (!images.length) {
            body.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:40px">No evidence images available</p>';
        } else {
            body.innerHTML = images.map((b64, i) => `
                <div class="evidence-img-wrap">
                    <img src="data:image/jpeg;base64,${b64}" alt="Evidence ${i + 1}"
                         class="evidence-full-img" onclick="this.classList.toggle('zoomed')">
                    <div class="evidence-img-label">Evidence Photo ${i + 1}</div>
                </div>
            `).join('');
        }

        modal.classList.add('active');
    } catch(e) {
        alert('Could not load evidence: ' + e.message);
    }
}

function closeEvidenceModal() {
    document.getElementById('evidence-modal').classList.remove('active');
}

async function acknowledgeAlert(alertId) {
    try {
        await fetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
        const el = document.getElementById(`alert-row-${alertId}`);
        if (el) el.style.opacity = '0.5';
        updateAlertBadge();
    } catch(e) {}
}

function updateAlertBadge() {
    fetch(`${API_BASE}/api/alerts/unacknowledged`)
        .then(r => r.json())
        .then(data => {
            const count = Array.isArray(data) ? data.length : 0;
            const badge = document.getElementById('alert-badge');
            const pill = document.getElementById('alerts-pill-value');
            badge.textContent = count;
            pill.textContent = count;
            badge.style.display = count > 0 ? 'inline' : 'none';
            // Turn pill red when there are alerts
            document.getElementById('stat-alerts-pill').classList.toggle('has-alerts', count > 0);
        })
        .catch(() => {});
}

async function refreshAlerts() {
    try {
        const res = await fetch(`${API_BASE}/api/alerts?limit=100`);
        const alerts = await res.json();
        const tbody = document.getElementById('alerts-tbody');
        tbody.innerHTML = '';

        if (!alerts.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px">No alerts recorded</td></tr>';
            return;
        }

        alerts.forEach(a => {
            const row = document.createElement('tr');
            row.id = `alert-row-${a.id}`;
            if (a.acknowledged) row.style.opacity = '0.5';

            const evidenceCell = a.evidence_thumb
                ? `<td><img src="data:image/jpeg;base64,${a.evidence_thumb}"
                       class="evidence-thumb" onclick="showEvidence('${a.id}')"
                       title="Click to view full evidence" alt="Evidence"></td>`
                : `<td><button class="btn-sm" onclick="showEvidence('${a.id}')">View</button></td>`;

            const policeCell = a.police_alerted
                ? `<td><span class="police-dispatched-tag">🚔 Dispatched</span></td>`
                : `<td><span style="color:var(--text-muted);font-size:0.78rem">—</span></td>`;

            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:0.78rem">${formatTime(a.timestamp)}</td>
                <td><strong style="color:var(--accent-red)">${escapeHtml(a.person_name?.replace('CONFIRMED: ','') || 'Unknown')}</strong>
                    <br><span style="font-size:0.72rem;color:var(--text-muted)">${escapeHtml(a.camera_id || '')}</span></td>
                <td><span class="conf-bar"><span class="conf-fill" style="width:${Math.min(100,a.confidence||0)}%"></span></span>
                    <span style="font-size:0.8rem">${a.confidence ? a.confidence + '%' : '—'}</span></td>
                <td>📍 ${escapeHtml(a.camera_location || '—')}</td>
                ${evidenceCell}
                ${policeCell}
                <td>${a.acknowledged
                    ? '<span style="color:var(--accent-green);font-size:0.82rem">✓ Ack</span>'
                    : `<button class="btn-sm" onclick="acknowledgeAlert('${a.id}')">Acknowledge</button>`
                }</td>
            `;
            tbody.appendChild(row);
        });
    } catch(e) { console.error('Fetch alerts error:', e); }
}

async function refreshPoliceLog() {
    try {
        const res = await fetch(`${API_BASE}/api/alerts/police?limit=100`);
        const dispatches = await res.json();
        const tbody = document.getElementById('police-tbody');
        tbody.innerHTML = '';

        if (!dispatches.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px">No police dispatches recorded</td></tr>';
            return;
        }

        dispatches.forEach(d => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:0.78rem">${formatTime(d.timestamp)}</td>
                <td><strong style="color:var(--accent-red)">${escapeHtml(d.criminal_name || 'Unknown')}</strong></td>
                <td>📍 ${escapeHtml(d.camera_location || '—')}</td>
                <td>${escapeHtml(d.camera_id || '—')}</td>
                <td>${d.confidence ? d.confidence + '%' : '—'}</td>
                <td><span class="police-dispatched-tag">${escapeHtml(d.action || 'DISPATCHED')}</span></td>
                <td style="font-size:0.78rem">${(d.gates_locked || []).join(' · ')}</td>
            `;
            tbody.appendChild(row);
        });
    } catch(e) { console.error('Fetch police log error:', e); }
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
    } catch(e) {}
}

// ─── Stats ──────────────────────────────────────────────
async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/api/stats`);
        const stats = await res.json();
        updateStatsUI(stats);
    } catch(e) {}
}

function updateStatsUI(stats) {
    document.getElementById('stat-total-cameras').textContent = stats.active_cameras || 0;
    document.getElementById('stat-total-detections').textContent = stats.total_detections || 0;
    document.getElementById('stat-total-alerts').textContent = stats.unacknowledged_alerts || 0;
    document.getElementById('stat-db-count').textContent = stats.criminals_in_db || 0;
    document.getElementById('fps-value').textContent = (stats.fps || 0).toFixed(1);
    document.getElementById('cameras-value').textContent = stats.active_cameras || 0;

    const el = (id, v) => { const e = document.getElementById(id); if(e) e.textContent = v; };
    el('info-uptime', formatUptime(stats.uptime_seconds || 0));
    el('info-detections', stats.total_detections || 0);
    el('info-fps', (stats.fps || 0).toFixed(1) + ' fps');
    el('info-cameras', stats.active_cameras || 0);
    el('info-watchlist', stats.criminals_in_db || 0);
}

// ─── Criminal Database ──────────────────────────────────
async function fetchCriminals() {
    try {
        const res = await fetch(`${API_BASE}/api/criminals`);
        const criminals = await res.json();
        renderCriminals(criminals);
    } catch(e) {}
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
        const imgCount = (c.images || []).length;
        const imgWarning = imgCount === 0
            ? `<div class="no-image-warning">⚠ No face images — detection disabled</div>` : '';

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
                <div class="criminal-info-row"><span class="label">Images</span><span class="value" style="color:${imgCount > 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">${imgCount} photo${imgCount !== 1 ? 's' : ''}</span></div>
                ${c.last_seen ? `<div class="criminal-info-row"><span class="label">Last Seen</span><span class="value" style="font-size:0.75rem">${escapeHtml(c.last_seen)}</span></div>` : ''}
                ${c.description ? `<div style="margin-top:8px;font-size:0.78rem;color:var(--text-secondary)">${escapeHtml(c.description)}</div>` : ''}
                ${imgWarning}
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
        const res = await fetch(`${API_BASE}/api/criminals`, { method: 'POST', body: formData });
        if (res.ok) {
            form.reset();
            toggleAddForm();
            fetchCriminals();
            fetchStats();
        } else {
            const err = await res.json();
            alert('Error: ' + (err.detail || err.error || 'Unknown error'));
        }
    } catch(e) { alert('Error adding criminal: ' + e.message); }
}

async function removeCriminal(id) {
    if (!confirm('Remove criminal from watchlist?')) return;
    try {
        await fetch(`${API_BASE}/api/criminals/${id}`, { method: 'DELETE' });
        fetchCriminals();
        fetchStats();
    } catch(e) { alert('Error: ' + e.message); }
}

// ─── Logs ───────────────────────────────────────────────
async function refreshLogs() {
    try {
        const res = await fetch(`${API_BASE}/api/logs?limit=200`);
        const logs = await res.json();
        const tbody = document.getElementById('logs-tbody');
        tbody.innerHTML = '';

        if (!logs.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:40px">No detections logged yet</td></tr>';
            return;
        }

        logs.forEach(log => {
            const threat = log.threat || 'Safe';
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family:var(--font-mono);font-size:0.78rem">${formatTime(log.timestamp)}</td>
                <td>${escapeHtml(log.person || '-')}</td>
                <td><span class="threat-tag threat-criminal">${threat}</span></td>
                <td>${log.confidence ? log.confidence + '%' : '-'}</td>
                <td>${escapeHtml(log.camera || '-')}</td>
                <td>${escapeHtml(log.location || '-')}</td>
            `;
            tbody.appendChild(row);
        });
    } catch(e) {}
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
    } catch(e) {}
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
    } catch(e) { alert('Error: ' + e.message); }
}

async function removeCamera(id) {
    if (!confirm(`Remove camera ${id}?`)) return;
    try {
        await fetch(`${API_BASE}/api/cameras/${id}`, { method: 'DELETE' });
        fetchCameraList();
    } catch(e) {}
}

// ─── Utilities ──────────────────────────────────────────
function updateDateTime() {
    const now = new Date();
    const opts = { year: 'numeric', month: 'short', day: '2-digit',
                   hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
    document.getElementById('datetime-display').textContent = now.toLocaleDateString('en-US', opts);
}

function formatTime(isoStr) {
    if (!isoStr) return '--';
    try {
        return new Date(isoStr).toLocaleTimeString('en-US',
            { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
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

// Close evidence modal on backdrop click
document.addEventListener('click', (e) => {
    if (e.target.id === 'evidence-modal') closeEvidenceModal();
});
