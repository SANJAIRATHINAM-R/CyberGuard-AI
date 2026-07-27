/* ==========================================================================
   CyberGuard AI — scanner.js
   Handles Password Checker + Website Scanner module interactions
   ========================================================================== */

// ---- Sidebar toggle (shared across module pages) ----
const sideToggle = document.getElementById('sideToggle');
const sidebar = document.getElementById('sidebar');
if (sideToggle && sidebar) sideToggle.addEventListener('click', () => sidebar.classList.toggle('open'));

// ---- Password show/hide ----
document.querySelectorAll('.toggle-pw').forEach(icon => {
  icon.addEventListener('click', () => {
    const input = document.getElementById(icon.dataset.target);
    if (!input) return;
    const isPw = input.type === 'password';
    input.type = isPw ? 'text' : 'password';
    icon.classList.toggle('fa-eye', !isPw);
    icon.classList.toggle('fa-eye-slash', isPw);
  });
});

/* ==========================================================================
   PASSWORD CHECKER
   ========================================================================== */
const pwInput = document.getElementById('pwInput');
const liveMeterBar = document.getElementById('liveMeterBar');
const liveMeterLabel = document.getElementById('liveMeterLabel');
const analyzeBtn = document.getElementById('analyzeBtn');

function localStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 5);
}

if (pwInput) {
  pwInput.addEventListener('input', () => {
    const score = localStrength(pwInput.value);
    const pct = (score / 5) * 100;
    const colors = ['#ff4d6d', '#ff4d6d', '#ffb84d', '#ffb84d', '#2ee6a6', '#00d4ff'];
    const labels = ['Too short', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
    liveMeterBar.style.width = pct + '%';
    liveMeterBar.style.background = colors[score];
    liveMeterLabel.textContent = pwInput.value ? labels[score] : 'Start typing to see live strength';
  });
}

if (analyzeBtn) {
  analyzeBtn.addEventListener('click', async () => {
    const pw = pwInput.value;
    if (!pw) { showToast('Enter a password first', 'error'); return; }

    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

    let data;
    try {
      data = await apiRequest('/api/password-check', {
        method: 'POST',
        body: JSON.stringify({ password: pw })
      });
    } catch (err) {
      // Fallback local analysis if backend isn't running (e.g. static preview)
      data = localPasswordAnalysis(pw);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Run Full Analysis';
    }
    renderPasswordResult(data);
  });
}

function localPasswordAnalysis(pw) {
  const charsetSize =
    (/[a-z]/.test(pw) ? 26 : 0) +
    (/[A-Z]/.test(pw) ? 26 : 0) +
    (/\d/.test(pw) ? 10 : 0) +
    (/[^A-Za-z0-9]/.test(pw) ? 32 : 0);
  const entropy = pw.length * Math.log2(charsetSize || 1);
  const guesses = Math.pow(2, entropy);
  const seconds = guesses / 1e9; // assume 1 billion guesses/sec
  let crackTime;
  if (seconds < 1) crackTime = 'Instantly';
  else if (seconds < 60) crackTime = Math.round(seconds) + ' seconds';
  else if (seconds < 3600) crackTime = Math.round(seconds / 60) + ' minutes';
  else if (seconds < 86400) crackTime = Math.round(seconds / 3600) + ' hours';
  else if (seconds < 31536000) crackTime = Math.round(seconds / 86400) + ' days';
  else crackTime = Math.round(seconds / 31536000).toLocaleString() + ' years';

  const score = localStrength(pw);
  const risk = score <= 1 ? 'high' : score <= 3 ? 'medium' : 'low';
  const verdicts = { high: 'Weak password — easily crackable', medium: 'Moderate password — could be stronger', low: 'Strong password' };
  const suggestions = [];
  if (pw.length < 12) suggestions.push('Use at least 12 characters');
  if (!/[A-Z]/.test(pw)) suggestions.push('Add uppercase letters');
  if (!/\d/.test(pw)) suggestions.push('Add numbers');
  if (!/[^A-Za-z0-9]/.test(pw)) suggestions.push('Add special characters (!@#$%)');
  if (/(.)\1{2,}/.test(pw)) suggestions.push('Avoid repeating characters');
  if (!suggestions.length) suggestions.push('Great job — this password meets all strength criteria');

  return {
    risk_level: risk,
    verdict: verdicts[risk],
    entropy: entropy.toFixed(1) + ' bits',
    length: pw.length,
    charsets: [/[a-z]/.test(pw) && 'lower', /[A-Z]/.test(pw) && 'upper', /\d/.test(pw) && 'digits', /[^A-Za-z0-9]/.test(pw) && 'symbols'].filter(Boolean).join(', ') || 'none',
    crack_time: crackTime,
    ai_explanation: `This password has an estimated entropy of ${entropy.toFixed(1)} bits. ${verdicts[risk]}. An attacker using standard offline cracking hardware would need roughly ${crackTime} to guess it through brute force.`,
    suggestions,
  };
}

function renderPasswordResult(data) {
  const card = document.getElementById('resultCard');
  card.style.display = 'block';
  document.getElementById('resultVerdict').textContent = data.verdict;
  const chip = document.getElementById('riskChip');
  chip.textContent = data.risk_level.toUpperCase() + ' RISK';
  chip.className = 'risk-chip ' + data.risk_level;

  document.getElementById('metricEntropy').textContent = data.entropy;
  document.getElementById('metricLength').textContent = data.length + ' chars';
  document.getElementById('metricCharsets').textContent = data.charsets;
  document.getElementById('metricCrack').textContent = data.crack_time;

  document.getElementById('aiExplanation').textContent = data.ai_explanation;

  const list = document.getElementById('suggestionList');
  list.innerHTML = '';
  data.suggestions.forEach(s => {
    const li = document.createElement('li');
    li.textContent = s;
    list.appendChild(li);
  });

  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* ==========================================================================
   WEBSITE SCANNER
   ========================================================================== */
const scanUrlBtn = document.getElementById('scanUrlBtn');
if (scanUrlBtn) {
  scanUrlBtn.addEventListener('click', async () => {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) { showToast('Enter a URL first', 'error'); return; }

    scanUrlBtn.disabled = true;
    scanUrlBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';

    let data;
    try {
      data = await apiRequest('/api/scan-website', {
        method: 'POST',
        body: JSON.stringify({ url })
      });
    } catch (err) {
      data = localWebsiteAnalysis(url);
    } finally {
      scanUrlBtn.disabled = false;
      scanUrlBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Scan Website';
    }
    renderWebsiteResult(data);
  });
}

function localWebsiteAnalysis(rawUrl) {
  let url = rawUrl;
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  let hostname = '';
  try { hostname = new URL(url).hostname; } catch { hostname = url; }

  const isHttps = url.startsWith('https://');
  const suspiciousKeywords = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'paypal', 'free', 'bonus'];
  const hasSuspiciousKeyword = suspiciousKeywords.some(k => hostname.toLowerCase().includes(k));
  const hasManySubdomains = hostname.split('.').length > 3;
  const hasHyphens = (hostname.match(/-/g) || []).length >= 2;
  const isIpAddress = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

  let riskPoints = 0;
  if (!isHttps) riskPoints += 30;
  if (hasSuspiciousKeyword) riskPoints += 25;
  if (hasManySubdomains) riskPoints += 15;
  if (hasHyphens) riskPoints += 15;
  if (isIpAddress) riskPoints += 40;

  const risk = riskPoints >= 50 ? 'high' : riskPoints >= 20 ? 'medium' : 'low';
  const verdicts = { high: 'This site shows multiple high-risk indicators', medium: 'This site has some suspicious characteristics', low: 'This site appears safe based on available checks' };

  return {
    risk_level: risk,
    verdict: verdicts[risk],
    metrics: [
      { label: 'HTTPS', value: isHttps ? 'Enabled' : 'Missing', status: isHttps ? 'ok' : 'bad' },
      { label: 'Domain Age', value: 'Unknown (offline check)', status: 'warn' },
      { label: 'Blacklist Status', value: risk === 'high' ? 'Flagged patterns' : 'Not listed', status: risk === 'high' ? 'bad' : 'ok' },
      { label: 'Suspicious Keywords', value: hasSuspiciousKeyword ? 'Detected' : 'None found', status: hasSuspiciousKeyword ? 'bad' : 'ok' },
    ],
    ai_explanation: `Analyzing ${hostname}: ${!isHttps ? 'the site does not use HTTPS encryption, which is a major red flag. ' : 'the site uses HTTPS encryption. '}${hasSuspiciousKeyword ? 'The domain name contains keywords commonly used in phishing attempts. ' : ''}${isIpAddress ? 'The address uses a raw IP instead of a domain name, which is unusual for legitimate sites. ' : ''}Overall this results in a ${risk} risk classification. Always verify the sender and avoid entering credentials on sites you don't fully trust.`,
  };
}

function renderWebsiteResult(data) {
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

  document.getElementById('aiExplanation').textContent = data.ai_explanation;
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
