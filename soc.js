/* ═══════════════════════════════════════════
   TOMATO SOC — Dashboard JS
   SocketIO • Chart.js • Real-time updates
═══════════════════════════════════════════ */

const socket = io({
  transports: ['polling'],
  upgrade: false
});

// ─── STATE ───────────────────────────────
let allLogs      = [];   // all received logs (newest first)
let filteredLogs = [];
let allAlerts    = [];
let allBlocked   = [];
let chartInstance = null;
let attackCounts = { SQL_INJECTION:0, XSS:0, DDOS:0, BRUTE_FORCE:0, MALWARE_TOOL:0, PHISHING_RECON:0 };
let totalReqs    = 0;

// ─── CLOCK ───────────────────────────────
function updateClock() {
  const now = new Date();

  const istTime = now.toLocaleTimeString("en-IN", {
    timeZone: "Asia/Kolkata",
    hour12: false
  });

  const istDate = now.toLocaleDateString("en-IN", {
    timeZone: "Asia/Kolkata",
    weekday: "short",
    day: "2-digit",
    month: "short",
    year: "numeric"
  }).toUpperCase();

  document.getElementById('clock').textContent =
    istTime + ' IST';

  document.getElementById('clockDate').textContent =
    istDate;
}

setInterval(updateClock, 1000);
updateClock();

// ─── SOCKETIO EVENTS ─────────────────────
socket.on('connect', () => {
  console.log("✅ CONNECTED TO SOC");
  document.getElementById('statusPill').className = 'status-pill';
  document.getElementById('statusPill').innerHTML = '<span class="pulse-dot"></span><span>CONNECTED</span>';
});

socket.on('disconnect', () => {
  document.getElementById('statusPill').className = 'status-pill offline';
  document.getElementById('statusPill').innerHTML = '<span class="pulse-dot"></span><span>OFFLINE</span>';
});

socket.on('init', (data) => {
  // Populate initial state
  totalReqs = data.stats.total_requests || 0;
  attackCounts = { SQL_INJECTION:0, XSS:0, DDOS:0, BRUTE_FORCE:0, MALWARE_TOOL:0, PHISHING_RECON:0, ...data.stats.attack_counts };
  allLogs    = (data.recent_logs || []).slice();
  allAlerts  = (data.recent_alerts || []).slice();
  allBlocked = (data.blocked_ips || []).slice();
  updateStats();
  rebuildTrafficTable();
  rebuildAlerts();
  rebuildBlocked();
  rebuildChart();
});

socket.on('new_log', (entry) => {
  allLogs.unshift(entry);
  if (allLogs.length > 500) allLogs.pop();
  totalReqs++;
  prependRow(entry);
  updateStats();
});

socket.on('new_alert', (alert) => {
  allAlerts.unshift(alert);
  if (allAlerts.length > 200) allAlerts.pop();
  attackCounts[alert.type] = (attackCounts[alert.type] || 0) + 1;
  prependAlert(alert);
  updateStats();
  rebuildChart();
  flashStat(alert.severity);
});

socket.on('ip_blocked', ({ ip, reason, ts }) => {
  allBlocked.unshift({ ip, reason, blocked_at: ts, expires: addHour(ts) });
  rebuildBlocked();
  showToast(`🚫 Blocked: ${ip} (${reason})`);
  // Mark any rows with that IP
  document.querySelectorAll(`.td-ip[data-ip="${ip}"]`).forEach(el => {
    el.classList.add('blocked-ip');
    el.title = 'IP BLOCKED';
  });
});

socket.on('ip_unblocked', ({ ip }) => {
  allBlocked = allBlocked.filter(b => b.ip !== ip);
  rebuildBlocked();
  showToast(`✅ Unblocked: ${ip}`);
});

// ─── STATS ───────────────────────────────
function updateStats() {
  setVal('scTotal',   totalReqs);
  setVal('scSql',     attackCounts.SQL_INJECTION || 0);
  setVal('scXss',     attackCounts.XSS           || 0);
  setVal('scDdos',    attackCounts.DDOS           || 0);
  setVal('scMalware', (attackCounts.MALWARE_TOOL  || 0) + (attackCounts.BRUTE_FORCE || 0));
  setVal('scBlocked', allBlocked.length);
}

function setVal(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  const prev = parseInt(el.textContent) || 0;
  if (val !== prev) {
    el.textContent = val;
    el.classList.add('bump');
    setTimeout(() => el.classList.remove('bump'), 300);
  }
}

function flashStat(severity) {
  const map = { HIGH:'sc-sql', CRITICAL:'sc-ddos', MEDIUM:'sc-xss' };
  const id = map[severity];
  if (!id) return;
  const card = document.querySelector('.' + id);
  if (card) { card.style.borderColor = 'var(--red)'; setTimeout(() => card.style.borderColor = '', 600); }
}

// ─── TRAFFIC TABLE ───────────────────────
function prependRow(entry) {
  const tbody = document.getElementById('trafficBody');
  const filter = document.getElementById('logFilter').value.toLowerCase();
  if (filter && !matchesFilter(entry, filter)) return;

  const tr = document.createElement('tr');
  tr.innerHTML = buildRow(entry);

  // Keep max 200 rows in DOM
  if (tbody.rows.length >= 200) tbody.deleteRow(tbody.rows.length - 1);
  tbody.insertBefore(tr, tbody.firstChild);
}

function rebuildTrafficTable() {
  const tbody = document.getElementById('trafficBody');
  const filter = document.getElementById('logFilter').value.toLowerCase();
  const shown = filter ? allLogs.filter(l => matchesFilter(l, filter)) : allLogs;
  tbody.innerHTML = shown.slice(0, 200).map(buildRow).join('');
}

function buildRow(e) {
  const isBlocked = allBlocked.some(b => b.ip === e.ip);
  const ipClass   = isBlocked ? 'blocked-ip' : '';
  const method    = (e.method || 'GET').toUpperCase();
  const mClass    = `method-${method.toLowerCase()}`;
  const threat    = e.primary_threat || 'CLEAN';
  const tClass    = threatClass(threat);
  const sev       = e.severity || 'NONE';
  const path      = escHtml(e.path || '/');
  const btnHtml   = isBlocked
    ? `<button class="unblock-btn" onclick="unblockIp('${e.ip}')">Unblock</button>`
    : threat !== 'CLEAN'
      ? `<button class="block-btn" onclick="blockIp('${e.ip}', '${threat}')">Block</button>`
      : '—';

  return `<tr>
    <td class="td-time">${escHtml(e.timestamp || '')}</td>
    <td class="td-ip ${ipClass}" data-ip="${escHtml(e.ip || '')}" title="${e.ip}">${escHtml(e.ip || '')}</td>
    <td class="td-method ${mClass}">${method}</td>
    <td class="td-path" title="${path}">${path}</td>
    <td class="td-threat ${tClass}">${threat}</td>
    <td><span class="sev-pill sev-${sev}">${sev}</span></td>
    <td>${btnHtml}</td>
  </tr>`;
}

function matchesFilter(entry, f) {
  return (entry.ip||'').includes(f) ||
         (entry.path||'').toLowerCase().includes(f) ||
         (entry.primary_threat||'').toLowerCase().includes(f) ||
         (entry.method||'').toLowerCase().includes(f);
}

function filterLogs() { rebuildTrafficTable(); }
function clearLogs()  { allLogs = []; document.getElementById('trafficBody').innerHTML = ''; totalReqs = 0; updateStats(); }

// ─── ALERTS ──────────────────────────────
function prependAlert(alert) {
  const list = document.getElementById('alertsList');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.innerHTML = buildAlertHtml(alert);
  list.insertBefore(div.firstElementChild, list.firstChild);

  // Keep max 50 alerts in DOM
  while (list.children.length > 50) list.removeChild(list.lastChild);
}

function rebuildAlerts() {
  const list = document.getElementById('alertsList');
  if (!allAlerts.length) {
    list.innerHTML = '<div class="empty-state">No alerts yet — system monitoring…</div>';
    return;
  }
  list.innerHTML = allAlerts.slice(0, 50).map(buildAlertHtml).join('');
}

function buildAlertHtml(a) {
  const blockedTag = a.blocked ? '<span class="alert-blocked-tag">BLOCKED</span>' : '';
  const ts = a.ts ? new Date(a.ts).toLocaleTimeString() : '';
  return `<div class="alert-item sev-${a.severity}">
    <div class="alert-header">
      <span class="alert-type">${a.type} ${blockedTag}</span>
      <span class="sev-pill sev-${a.severity}">${a.severity}</span>
    </div>
    <div class="alert-ip">${escHtml(a.ip)} <span style="color:var(--dim)">· ${ts}</span></div>
    <div class="alert-detail" title="${escHtml(a.detail||'')}">↳ ${escHtml((a.detail||'').slice(0,80))}</div>
  </div>`;
}

function clearAlerts() { allAlerts = []; rebuildAlerts(); }

// ─── CHART ───────────────────────────────
function rebuildChart() {
  const ctx = document.getElementById('attackChart').getContext('2d');
  const labels = ['SQLi','XSS','DDoS','BruteForce','Malware','Phishing'];
  const data   = [
    attackCounts.SQL_INJECTION || 0,
    attackCounts.XSS           || 0,
    attackCounts.DDOS          || 0,
    attackCounts.BRUTE_FORCE   || 0,
    attackCounts.MALWARE_TOOL  || 0,
    attackCounts.PHISHING_RECON|| 0,
  ];
  const colors = ['#FF3B5C','#FF7A00','#A855F7','#FFD100','#FF3B5C','#00BFFF'];

  if (chartInstance) {
    chartInstance.data.datasets[0].data = data;
    chartInstance.update('none');
    return;
  }

  chartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => c + '33'),
        borderColor:      colors,
        borderWidth: 2,
        hoverBackgroundColor: colors.map(c => c + '66'),
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#7A9AB0',
            font: { family: 'Rajdhani', size: 11, weight: '600' },
            padding: 10, boxWidth: 12,
          }
        },
        tooltip: {
          backgroundColor: '#0D1520',
          borderColor: '#1A2A3A', borderWidth: 1,
          titleColor: '#C8D8E8', bodyColor: '#7A9AB0',
          titleFont: { family: 'Rajdhani', size: 12 },
        }
      },
      cutout: '65%',
    }
  });
}

// ─── BLOCKED IPs TABLE ───────────────────
function rebuildBlocked() {
  const tbody = document.getElementById('blockedBody');
  const filter = document.getElementById('blockFilter').value.toLowerCase();
  const shown = filter ? allBlocked.filter(b => b.ip.includes(filter)) : allBlocked;
  if (!shown.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-td">No blocked IPs</td></tr>';
    return;
  }
  tbody.innerHTML = shown.map(b => `
    <tr>
      <td class="td-ip" style="color:var(--red)">${escHtml(b.ip)}</td>
      <td class="td-threat threat-malware">${escHtml(b.reason)}</td>
      <td class="td-time">${b.blocked_at ? new Date(b.blocked_at).toLocaleString() : '—'}</td>
      <td class="td-time">${b.expires   ? new Date(b.expires).toLocaleString()   : '—'}</td>
      <td><button class="unblock-btn" onclick="unblockIp('${escHtml(b.ip)}')">Unblock</button></td>
    </tr>`).join('');
  setVal('scBlocked', allBlocked.length);
}

function filterBlocked() { rebuildBlocked(); }

// ─── BLOCK / UNBLOCK ─────────────────────
async function blockIp(ip, reason) {
  try {
    await fetch('/api/block', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip, reason})
    });
    showToast(`🚫 Blocked ${ip}`);
  } catch(e) { showToast('❌ Block failed'); }
}

async function unblockIp(ip) {
  try {
    await fetch('/api/unblock', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip})
    });
    showToast(`✅ Unblocked ${ip}`);
  } catch(e) { showToast('❌ Unblock failed'); }
}

function openManualBlock() { document.getElementById('blockModal').classList.add('open'); }
function closeModal(e) { if (e.target === e.currentTarget) e.currentTarget.classList.remove('open'); }

async function submitManualBlock() {
  const ip     = document.getElementById('manualIp').value.trim();
  const reason = document.getElementById('manualReason').value.trim() || 'MANUAL_BLOCK';
  if (!ip) { showToast('Enter an IP address'); return; }
  await blockIp(ip, reason);
  document.getElementById('blockModal').classList.remove('open');
  document.getElementById('manualIp').value = '';
}

// ─── EXPORTS ─────────────────────────────
function exportPCAP(threatsOnly = false) {
  const url = `/api/export/pcap?limit=2000&threats_only=${threatsOnly}`;
  showToast('📦 Generating PCAP…');
  window.location.href = url;
}
function exportJSON() { window.location.href = '/api/export/logs/json'; showToast('📋 Exporting JSON…'); }
function exportCSV()  { window.location.href = '/api/export/logs/csv';  showToast('📊 Exporting CSV…'); }

// ─── SIMULATE ────────────────────────────
async function simulateAttack() {
  try {
    const r = await fetch('/api/simulate', { method:'POST' });
    const d = await r.json();
    showToast(`⚡ Simulated ${d.count} attack events`);
  } catch(e) { showToast('❌ Simulation failed'); }
}

// ─── HELPERS ─────────────────────────────
function threatClass(t) {
  const map = {
    CLEAN:'threat-clean', SQL_INJECTION:'threat-sql', XSS:'threat-xss',
    DDOS:'threat-ddos', BRUTE_FORCE:'threat-brute',
    MALWARE_TOOL:'threat-malware', PHISHING_RECON:'threat-phishing'
  };
  return map[t] || '';
}

function escHtml(s) {
  if (typeof s !== 'string') return String(s || '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function addHour(isoStr) {
  try { const d = new Date(isoStr); d.setHours(d.getHours()+1); return d.toISOString(); }
  catch { return isoStr; }
}

let toastTimer;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}

// ─── INIT ─────────────────────────────────
rebuildChart();


