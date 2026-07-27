/* ==========================================================================
   CyberGuard AI — logscan.js
   Log Analyzer: file upload / paste, backend call with local JS fallback
   ========================================================================== */

const logDropZone = document.getElementById('logDropZone');
const logFileInput = document.getElementById('logFileInput');
const logFileChip = document.getElementById('logFileChip');
const logFileName = document.getElementById('logFileName');
const logFileSize = document.getElementById('logFileSize');
const logFileRemove = document.getElementById('logFileRemove');
const logRawInput = document.getElementById('logRawInput');
const analyzeLogBtn = document.getElementById('analyzeLogBtn');
const logProgress = document.getElementById('logProgress');

let selectedLogFile = null;

function formatBytesLog(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

if (logDropZone) {
  logDropZone.addEventListener('click', () => logFileInput.click());
  logDropZone.addEventListener('dragover', (e) => { e.preventDefault(); logDropZone.classList.add('dragover'); });
  logDropZone.addEventListener('dragleave', () => logDropZone.classList.remove('dragover'));
  logDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    logDropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleLogFile(e.dataTransfer.files[0]);
  });
  logFileInput.addEventListener('change', () => {
    if (logFileInput.files.length) handleLogFile(logFileInput.files[0]);
  });
}

function handleLogFile(file) {
  selectedLogFile = file;
  logFileName.textContent = file.name;
  logFileSize.textContent = formatBytesLog(file.size);
  logFileChip.style.display = 'flex';
  logDropZone.style.display = 'none';
}

if (logFileRemove) {
  logFileRemove.addEventListener('click', () => {
    selectedLogFile = null;
    logFileInput.value = '';
    logFileChip.style.display = 'none';
    logDropZone.style.display = 'block';
  });
}

analyzeLogBtn.addEventListener('click', async () => {
  const rawText = logRawInput.value.trim();
  if (!selectedLogFile && !rawText) {
    showToast('Upload a log file or paste log content first', 'error');
    return;
  }

  analyzeLogBtn.disabled = true;
  logProgress.classList.add('active');
  analyzeLogBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

  let data;
  try {
    if (selectedLogFile) {
      const formData = new FormData();
      formData.append('file', selectedLogFile);
      const res = await fetch('/api/analyze-log', { method: 'POST', body: formData, credentials: 'same-origin' });
      data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Analysis failed');
    } else {
      data = await apiRequest('/api/analyze-log', { method: 'POST', body: JSON.stringify({ raw: rawText }) });
    }
  } catch (err) {
    const text = selectedLogFile ? await selectedLogFile.text() : rawText;
    data = localLogAnalysis(text);
  } finally {
    analyzeLogBtn.disabled = false;
    logProgress.classList.remove('active');
    analyzeLogBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Analyze Log';
  }
  renderLogResult(data);
});

const LOG_PATTERNS = {
  'SQL Injection': [/\bunion\b.{0,20}\bselect\b/i, /(\bor\b|\|\|)\s*'?\d+'?\s*=\s*'?\d+'?/i, /\bdrop\s+table\b/i, /information_schema/i],
  'Cross-Site Scripting (XSS)': [/<script.*?>/i, /javascript\s*:/i, /onerror\s*=|onload\s*=/i, /%3Cscript/i],
  'Directory Traversal': [/\.\.\/|\.\.\\/, /%2e%2e%2f/i, /\/etc\/passwd/, /\bwin\.ini\b/i],
  'Command Injection': [/;\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b/, /\|\s*(cat|ls|whoami|id|nc|bash)\b/, /\$\(.*\)/, /`.*`/],
};

function severityFor(category) {
  return { 'SQL Injection': 'high', 'Command Injection': 'high', 'Directory Traversal': 'medium', 'Cross-Site Scripting (XSS)': 'medium' }[category] || 'low';
}

function safeDecodeURIComponent(str) {
  try { return decodeURIComponent(str); } catch { return str; }
}

function localLogAnalysis(text) {
  const lines = text.split('\n').filter(l => l.trim());
  const findings = [];
  const categoryCounts = {};

  lines.forEach((line, idx) => {
    const decodedLine = safeDecodeURIComponent(line);
    for (const [category, patterns] of Object.entries(LOG_PATTERNS)) {
      if (patterns.some(p => p.test(line) || p.test(decodedLine))) {
        findings.push({ severity: severityFor(category), label: category, line: idx + 1, detail: line.trim().slice(0, 220) });
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
        break;
      }
    }
  });

  // Brute force: repeated 401/403 on login-like paths from same IP
  const ipFailures = {};
  const ipRegex = /^(\d{1,3}(?:\.\d{1,3}){3})/;
  const statusRegex = /"\s(\d{3})(?:\s|$)/;
  const loginRegex = /(login|signin|auth|wp-login)/i;
  lines.forEach(line => {
    const ipMatch = line.match(ipRegex);
    const statusMatch = line.match(statusRegex);
    if (ipMatch && loginRegex.test(line) && statusMatch && ['401', '403'].includes(statusMatch[1])) {
      ipFailures[ipMatch[1]] = (ipFailures[ipMatch[1]] || 0) + 1;
    }
  });
  Object.entries(ipFailures).forEach(([ip, count]) => {
    if (count >= 5) {
      findings.push({ severity: 'high', label: 'Brute Force', line: null, detail: `${count} failed login attempts from ${ip}` });
      categoryCounts['Brute Force'] = (categoryCounts['Brute Force'] || 0) + 1;
    }
  });

  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const risk = highCount > 0 ? 'high' : mediumCount > 0 ? 'medium' : 'low';
  const verdict = highCount > 0 ? `${highCount} high-severity attack pattern(s) detected`
    : mediumCount > 0 ? `${mediumCount} medium-severity pattern(s) detected`
    : 'No attack patterns detected in this log';

  let explanation;
  const catEntries = Object.entries(categoryCounts);
  if (catEntries.length) {
    const top = catEntries.map(([k, v]) => `${k} (${v})`).join(', ');
    explanation = `Analyzed ${lines.length} log line(s) and found ${findings.length} suspicious entries across these categories: ${top}. `;
    explanation += highCount
      ? 'The high-severity findings suggest active attack attempts rather than incidental traffic — investigate the source IPs and consider blocking them at the firewall or WAF level.'
      : 'These are lower-severity patterns; monitor for repetition but they may also be false positives from legitimate traffic containing special characters.';
  } else {
    explanation = `Analyzed ${lines.length} log line(s) and found no known SQL injection, XSS, traversal, command injection, or brute-force patterns.`;
  }

  return {
    risk_level: risk,
    verdict,
    metrics: [
      { label: 'Lines Analyzed', value: String(lines.length), status: 'ok' },
      { label: 'Total Findings', value: String(findings.length), status: findings.length ? 'bad' : 'ok' },
      { label: 'High Severity', value: String(highCount), status: highCount ? 'bad' : 'ok' },
      { label: 'Categories Matched', value: String(catEntries.length), status: catEntries.length ? 'warn' : 'ok' },
    ],
    findings: findings.slice(0, 100),
    ai_explanation: explanation,
  };
}

function renderLogResult(data) {
  const card = document.getElementById('resultCard');
  card.style.display = 'block';
  document.getElementById('resultVerdict').textContent = data.verdict;
  const chip = document.getElementById('riskChip');
  chip.textContent = data.risk_level.toUpperCase() + ' RISK';
  chip.className = 'risk-chip ' + data.risk_level;

  const grid = document.getElementById('metricGrid');
  grid.innerHTML = '';
  data.metrics.forEach(m => {
    const div = document.createElement('div');
    div.className = 'metric ' + m.status;
    div.innerHTML = `<span>${m.label}</span><strong>${m.value}</strong>`;
    grid.appendChild(div);
  });

  const list = document.getElementById('findingsList');
  list.innerHTML = '';
  if (!data.findings.length) {
    list.innerHTML = '<div class="no-findings"><i class="fa-solid fa-shield-halved"></i>No attack patterns found in this log.</div>';
  } else {
    data.findings.forEach(f => {
      const div = document.createElement('div');
      div.className = 'finding-item ' + f.severity;
      const icon = f.severity === 'high' ? 'fa-circle-exclamation' : f.severity === 'medium' ? 'fa-triangle-exclamation' : 'fa-circle-info';
      const lineLabel = f.line ? `Line ${f.line}` : 'Pattern match';
      div.innerHTML = `<i class="fa-solid ${icon}"></i><div class="finding-body"><span class="finding-tag">${f.severity} · ${lineLabel}</span><strong>${f.label}</strong><code>${escapeHtml(f.detail)}</code></div>`;
      list.appendChild(div);
    });
  }

  document.getElementById('aiExplanation').textContent = data.ai_explanation;
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
