/* ==========================================================================
   CyberGuard AI — email.js
   Email Analyzer: file upload / paste, backend call with local JS fallback
   ========================================================================== */

const emailDropZone = document.getElementById('emailDropZone');
const emailFileInput = document.getElementById('emailFileInput');
const emailFileChip = document.getElementById('emailFileChip');
const emailFileName = document.getElementById('emailFileName');
const emailFileSize = document.getElementById('emailFileSize');
const emailFileRemove = document.getElementById('emailFileRemove');
const emailRawInput = document.getElementById('emailRawInput');
const analyzeEmailBtn = document.getElementById('analyzeEmailBtn');
const emailProgress = document.getElementById('emailProgress');

let selectedEmailFile = null;

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

if (emailDropZone) {
  emailDropZone.addEventListener('click', () => emailFileInput.click());
  emailDropZone.addEventListener('dragover', (e) => { e.preventDefault(); emailDropZone.classList.add('dragover'); });
  emailDropZone.addEventListener('dragleave', () => emailDropZone.classList.remove('dragover'));
  emailDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    emailDropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleEmailFile(e.dataTransfer.files[0]);
  });
  emailFileInput.addEventListener('change', () => {
    if (emailFileInput.files.length) handleEmailFile(emailFileInput.files[0]);
  });
}

function handleEmailFile(file) {
  selectedEmailFile = file;
  emailFileName.textContent = file.name;
  emailFileSize.textContent = formatBytes(file.size);
  emailFileChip.style.display = 'flex';
  emailDropZone.style.display = 'none';
}

if (emailFileRemove) {
  emailFileRemove.addEventListener('click', () => {
    selectedEmailFile = null;
    emailFileInput.value = '';
    emailFileChip.style.display = 'none';
    emailDropZone.style.display = 'block';
  });
}

analyzeEmailBtn.addEventListener('click', async () => {
  const rawText = emailRawInput.value.trim();
  if (!selectedEmailFile && !rawText) {
    showToast('Upload an .eml file or paste email content first', 'error');
    return;
  }

  analyzeEmailBtn.disabled = true;
  emailProgress.classList.add('active');
  analyzeEmailBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

  let data;
  try {
    if (selectedEmailFile) {
      const formData = new FormData();
      formData.append('file', selectedEmailFile);
      const res = await fetch('/api/analyze-email', { method: 'POST', body: formData, credentials: 'same-origin' });
      data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Analysis failed');
    } else {
      data = await apiRequest('/api/analyze-email', { method: 'POST', body: JSON.stringify({ raw: rawText }) });
    }
  } catch (err) {
    // Fallback: run the same heuristics client-side
    const text = selectedEmailFile ? await selectedEmailFile.text() : rawText;
    data = localEmailAnalysis(text);
  } finally {
    analyzeEmailBtn.disabled = false;
    emailProgress.classList.remove('active');
    analyzeEmailBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Analyze Email';
  }
  renderEmailResult(data);
});

const PHISHING_KEYWORDS = [
  "verify your account", "account suspended", "confirm your identity",
  "urgent action required", "click here immediately", "your account has been locked",
  "update your payment", "unusual activity", "security alert", "act now",
  "limited time", "claim your prize", "you have won", "password expires",
  "unauthorized login attempt", "verify now", "reactivate",
];

function extractDomain(addr) {
  const m = (addr || '').match(/@([\w.-]+)/);
  return m ? m[1].toLowerCase() : '';
}

function localEmailAnalysis(rawText) {
  const fromMatch = rawText.match(/^From:\s*(.+)$/im);
  const replyMatch = rawText.match(/^Reply-To:\s*(.+)$/im);
  const subjectMatch = rawText.match(/^Subject:\s*(.+)$/im);

  const fromDomain = extractDomain(fromMatch ? fromMatch[1] : '');
  const replyDomain = extractDomain(replyMatch ? replyMatch[1] : '');
  const subject = subjectMatch ? subjectMatch[1] : '';

  const spoofing = !!(replyDomain && fromDomain && replyDomain !== fromDomain);
  const lowerText = (subject + '\n' + rawText).toLowerCase();
  const matchedKeywords = PHISHING_KEYWORDS.filter(k => lowerText.includes(k));

  const urlRegex = /https?:\/\/[^\s"'<>)]+/g;
  const links = [...new Set(rawText.match(urlRegex) || [])];
  const suspiciousUrlKeywords = ['login', 'verify', 'secure', 'update', 'account', 'confirm', 'bank'];
  const linkFindings = links.map(url => ({
    url,
    suspicious: suspiciousUrlKeywords.some(k => url.toLowerCase().includes(k)) || /bit\.ly|tinyurl|t\.co|goo\.gl/i.test(url),
  }));
  const suspiciousLinks = linkFindings.filter(l => l.suspicious);

  let riskPoints = 0;
  if (spoofing) riskPoints += 35;
  riskPoints += Math.min(matchedKeywords.length * 12, 36);
  riskPoints += Math.min(suspiciousLinks.length * 15, 30);

  const risk = riskPoints >= 55 ? 'high' : riskPoints >= 25 ? 'medium' : 'low';
  const verdicts = {
    high: 'This email shows strong signs of phishing',
    medium: 'This email has some suspicious characteristics',
    low: 'This email appears legitimate based on available checks',
  };

  const parts = [];
  if (spoofing) parts.push(`'From' domain (${fromDomain}) differs from 'Reply-To' domain (${replyDomain}).`);
  if (matchedKeywords.length) parts.push(`The message contains ${matchedKeywords.length} phrase(s) commonly used in phishing attempts, such as "${matchedKeywords[0]}".`);
  if (suspiciousLinks.length) parts.push(`${suspiciousLinks.length} of the ${links.length} link(s) found use wording or shorteners typical of credential-harvesting pages.`);
  if (!parts.length) parts.push('No spoofing indicators, phishing phrases, or suspicious links were found.');
  parts.push(`Overall this results in a ${risk} risk classification.`);

  return {
    risk_level: risk,
    verdict: verdicts[risk],
    metrics: [
      { label: 'Sender Spoofing', value: spoofing ? 'Detected' : 'Not detected', status: spoofing ? 'bad' : 'ok' },
      { label: 'Phishing Keywords', value: matchedKeywords.length ? `${matchedKeywords.length} found` : 'None found', status: matchedKeywords.length ? 'bad' : 'ok' },
      { label: 'Suspicious Links', value: `${suspiciousLinks.length} of ${links.length}`, status: suspiciousLinks.length ? 'bad' : (links.length ? 'warn' : 'ok') },
      { label: 'Risky Attachments', value: 'Not checked (client-side)', status: 'warn' },
    ],
    links: linkFindings,
    ai_explanation: parts.join(' '),
  };
}

function renderEmailResult(data) {
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

  const linkList = document.getElementById('linkList');
  linkList.innerHTML = '';
  if (!data.links || !data.links.length) {
    linkList.innerHTML = '<li><i class="fa-solid fa-circle-check"></i> No links found in this email</li>';
  } else {
    data.links.forEach(l => {
      const li = document.createElement('li');
      if (l.suspicious) li.classList.add('suspicious');
      li.innerHTML = `<i class="fa-solid ${l.suspicious ? 'fa-triangle-exclamation' : 'fa-link'}"></i> ${l.url}`;
      linkList.appendChild(li);
    });
  }

  document.getElementById('aiExplanation').textContent = data.ai_explanation;
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
