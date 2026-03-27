/* ═══════════════════════════════════════════════════════════
   URLGuard — Frontend Application Logic
   ═══════════════════════════════════════════════════════════ */

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const urlInput    = document.getElementById('urlInput');
const scanBtn     = document.getElementById('scanBtn');
const clearBtn    = document.getElementById('clearBtn');
const resultPanel = document.getElementById('resultPanel');
const resultLoading = document.getElementById('resultLoading');
const resultContent = document.getElementById('resultContent');
const bulkInput   = document.getElementById('bulkInput');
const bulkScanBtn = document.getElementById('bulkScanBtn');
const bulkResults = document.getElementById('bulkResults');
const historyList = document.getElementById('historyList');
const statTotal   = document.getElementById('statTotal');
const statThreats = document.getElementById('statThreats');

// ─── State ────────────────────────────────────────────────────────────────────
let isScanning = false;

// ─── Input handling ───────────────────────────────────────────────────────────
urlInput.addEventListener('input', () => {
  clearBtn.style.display = urlInput.value ? 'block' : 'none';
});

clearBtn.addEventListener('click', () => {
  urlInput.value = '';
  clearBtn.style.display = 'none';
  urlInput.focus();
  hideResults();
});

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !isScanning) triggerScan();
});

scanBtn.addEventListener('click', () => {
  if (!isScanning) triggerScan();
});

// ─── Demo URL helper ──────────────────────────────────────────────────────────
function setDemo(url) {
  urlInput.value = url;
  clearBtn.style.display = 'block';
  urlInput.focus();
  document.querySelector('#scanner').scrollIntoView({ behavior: 'smooth' });
}

// ─── Main scan trigger ────────────────────────────────────────────────────────
async function triggerScan() {
  const url = urlInput.value.trim();
  if (!url) {
    shake(urlInput.closest('.input-wrap'));
    return;
  }

  isScanning = true;
  scanBtn.disabled = true;
  scanBtn.querySelector('.scan-btn-text').textContent = 'Scanning…';

  showLoading();

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await response.json();

    if (data.error) {
      showError(data.error);
    } else {
      renderResult(data);
      refreshStats();
      refreshHistory();
    }
  } catch (err) {
    showError('Connection error — is the server running?');
  } finally {
    isScanning = false;
    scanBtn.disabled = false;
    scanBtn.querySelector('.scan-btn-text').textContent = 'Scan Now';
  }
}

// ─── Render result ────────────────────────────────────────────────────────────
function renderResult(d) {
  const cls = d.predicted_class;
  const riskBarColor = {
    benign: '#10b981', phishing: '#ef4444', defacement: '#f59e0b', malware: '#dc2626'
  }[cls] || '#94a3b8';

  const probColors = {
    benign: '#10b981', phishing: '#ef4444', defacement: '#f59e0b', malware: '#dc2626'
  };

  const threatDetailsHTML = d.threat_details.map(t => `
    <div class="detail-item">
      <div class="detail-icon ${t.type}">
        ${t.icon.length > 2 ? `<span>${t.icon}</span>` : t.icon}
      </div>
      <div class="detail-text">
        <h5>${escHtml(t.title)}</h5>
        <p>${escHtml(t.desc)}</p>
      </div>
    </div>
  `).join('');

  const probHTML = Object.entries(d.probabilities).map(([name, pct]) => `
    <div class="prob-item">
      <div class="prob-name">${name}</div>
      <div class="prob-bar-track">
        <div class="prob-bar-fill" style="width:${pct}%;background:${probColors[name] || '#94a3b8'}"></div>
      </div>
      <div class="prob-val color-${name}">${pct}%</div>
    </div>
  `).join('');

  const f = d.features;
  const featChips = [
    { label: 'URL Length',        value: f.url_length, unit: 'chars' },
    { label: 'Dot Count',         value: f.num_dots },
    { label: 'Subdomains',        value: f.num_subdomains },
    { label: 'Query Params',      value: f.num_query_params },
    { label: 'URL Entropy',       value: f.url_entropy?.toFixed(2) },
    { label: 'Hostname Entropy',  value: f.hostname_entropy?.toFixed(2) },
    { label: 'Suspicious KWs',    value: f.num_suspicious_kw },
    { label: 'HTTPS',             value: f.has_https,       type: 'bool' },
    { label: 'IP Address',        value: f.has_ip_address,  type: 'bool_danger' },
    { label: 'High-Risk TLD',     value: f.is_high_risk_tld, type: 'bool_danger' },
  ];

  const featHTML = featChips.map(fc => {
    let valClass = '';
    let displayVal = fc.value;
    if (fc.type === 'bool')        { displayVal = fc.value ? 'Yes' : 'No'; valClass = fc.value ? 'flag-true' : 'flag-false'; }
    if (fc.type === 'bool_danger') { displayVal = fc.value ? 'Yes' : 'No'; valClass = fc.value ? 'flag-true' : 'flag-false'; }
    if (fc.unit) displayVal = `${fc.value} ${fc.unit}`;
    return `
      <div class="feat-chip">
        <div class="feat-chip-label">${fc.label}</div>
        <div class="feat-chip-value ${valClass}">${displayVal}</div>
      </div>
    `;
  }).join('');

  const html = `
    <div class="result-box border-${cls}">
      <div class="result-header">
        <div class="result-verdict-icon bg-${cls} color-${cls}">
          ${d.risk_icon}
        </div>
        <div class="result-verdict-info">
          <div class="result-verdict-label color-${cls}">${d.risk_label}</div>
          <div class="result-url-display">${escHtml(d.url)}</div>
        </div>
        <div class="result-confidence-badge">
          <span class="result-confidence-num color-${cls}">${d.confidence}%</span>
          <span class="result-confidence-label">Confidence</span>
        </div>
      </div>

      <div class="risk-bar-section">
        <div class="risk-bar-label">
          <span>Risk Score</span>
          <span class="color-${cls}">${d.risk_score}/100</span>
        </div>
        <div class="risk-bar-track">
          <div class="risk-bar-fill" id="riskBarFill" style="width:0%;background:${riskBarColor}"></div>
        </div>
      </div>

      <div class="threat-details">
        <h4>Threat Indicators</h4>
        ${threatDetailsHTML}
      </div>

      <div class="prob-section">
        <h4>Classification Probabilities</h4>
        <div class="prob-grid">${probHTML}</div>
      </div>

      <div class="feature-snap">
        <h4>URL Feature Snapshot</h4>
        <div class="feature-snap-grid">${featHTML}</div>
      </div>

      <div class="result-meta">
        <span>⏱ ${d.scan_time_ms}ms</span>
        <span>📅 ${d.scanned_at}</span>
        <span>🔑 ID: ${d.scan_id}</span>
        <span>🌐 Host: ${escHtml(d.hostname)}</span>
      </div>
    </div>
  `;

  resultLoading.style.display = 'none';
  resultContent.innerHTML = html;
  resultContent.style.display = 'block';
  resultPanel.style.display = 'block';

  // Animate risk bar
  setTimeout(() => {
    const bar = document.getElementById('riskBarFill');
    if (bar) bar.style.width = d.risk_score + '%';
  }, 100);

  // Scroll to result
  resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Bulk scan ────────────────────────────────────────────────────────────────
bulkScanBtn.addEventListener('click', async () => {
  const raw = bulkInput.value.trim();
  if (!raw) return;

  const urls = raw.split('\n').map(u => u.trim()).filter(u => u).slice(0, 10);
  if (!urls.length) return;

  bulkScanBtn.disabled = true;
  bulkScanBtn.querySelector('span').textContent = 'Scanning…';
  bulkResults.style.display = 'none';

  try {
    const res = await fetch('/api/scan-bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls })
    });
    const data = await res.json();

    if (data.results) {
      renderBulkResults(data.results);
      refreshStats();
      refreshHistory();
    }
  } catch (e) {
    bulkResults.innerHTML = `<div class="history-empty">Error: ${e.message}</div>`;
    bulkResults.style.display = 'block';
  } finally {
    bulkScanBtn.disabled = false;
    bulkScanBtn.querySelector('span').textContent = 'Scan All';
  }
});

function renderBulkResults(results) {
  bulkResults.innerHTML = results.map(r => {
    if (r.error) {
      return `<div class="bulk-result-row">
        <span class="bulk-result-icon">⚠</span>
        <span class="bulk-result-url">${escHtml(r.url)}</span>
        <span class="bulk-result-label" style="color:#94a3b8">Error</span>
      </div>`;
    }
    const cls = r.predicted_class;
    return `<div class="bulk-result-row">
      <span class="bulk-result-icon color-${cls}">${r.risk_icon}</span>
      <span class="bulk-result-url">${escHtml(r.url)}</span>
      <span class="bulk-result-label color-${cls}">${r.risk_label}</span>
      <span class="bulk-result-score">${r.confidence}% · ${r.scan_time_ms}ms</span>
    </div>`;
  }).join('');
  bulkResults.style.display = 'flex';
}

// ─── Stats & History refresh ──────────────────────────────────────────────────
async function refreshStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    if (statTotal)   statTotal.textContent   = data.total_scanned;
    if (statThreats) statThreats.textContent = data.threats_found;
  } catch (_) {}
}

async function refreshHistory() {
  try {
    const res  = await fetch('/api/history');
    const data = await res.json();
    renderHistory(data.history || []);
  } catch (_) {}
}

function renderHistory(items) {
  if (!items.length) {
    historyList.innerHTML = '<div class="history-empty">No scans yet — try the scanner above ↑</div>';
    return;
  }
  historyList.innerHTML = items.map(item => `
    <div class="history-item">
      <div class="history-badge bg-${item.class} color-${item.class}">${item.icon}</div>
      <div class="history-url" title="${escHtml(item.url)}">${escHtml(item.url)}</div>
      <div class="history-label color-${item.class}">${item.label}</div>
      <div class="history-time">${item.time.split(' ')[1] || item.time}</div>
    </div>
  `).join('');
}

// ─── UI helpers ───────────────────────────────────────────────────────────────
function showLoading() {
  resultPanel.style.display = 'block';
  resultLoading.style.display = 'flex';
  resultContent.style.display = 'none';
}

function hideResults() {
  resultPanel.style.display = 'none';
}

function showError(msg) {
  resultLoading.style.display = 'none';
  resultContent.innerHTML = `
    <div style="background:var(--surface);border:1px solid var(--red-dim);border-radius:12px;padding:28px;text-align:center;color:var(--red)">
      <div style="font-size:2rem;margin-bottom:12px">⚠</div>
      <strong>${escHtml(msg)}</strong>
    </div>`;
  resultContent.style.display = 'block';
}

function shake(el) {
  el.style.animation = 'none';
  el.offsetHeight; // reflow
  el.style.animation = 'shake 0.4s ease';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Shake keyframe
const style = document.createElement('style');
style.textContent = `
  @keyframes shake {
    0%,100%{transform:translateX(0)}
    20%{transform:translateX(-6px)}
    40%{transform:translateX(6px)}
    60%{transform:translateX(-4px)}
    80%{transform:translateX(4px)}
  }
`;
document.head.appendChild(style);

// ─── Init ─────────────────────────────────────────────────────────────────────
(async () => {
  await refreshHistory();
  urlInput.focus();
})();
