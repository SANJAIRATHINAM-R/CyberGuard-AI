/* ==========================================================================
   CyberGuard AI — filescan.js
   File Scanner: upload, SHA-256 + risk analysis via backend, local fallback
   ========================================================================== */

const fileDropZone = document.getElementById('fileDropZone');
const scanFileInput = document.getElementById('scanFileInput');
const scanFileChip = document.getElementById('scanFileChip');
const scanFileName = document.getElementById('scanFileName');
const scanFileSize = document.getElementById('scanFileSize');
const scanFileRemove = document.getElementById('scanFileRemove');
const scanFileBtn = document.getElementById('scanFileBtn');
const fileProgress = document.getElementById('fileProgress');

let selectedScanFile = null;

if (fileDropZone) {
  fileDropZone.addEventListener('click', () => scanFileInput.click());
  fileDropZone.addEventListener('dragover', (e) => { e.preventDefault(); fileDropZone.classList.add('dragover'); });
  fileDropZone.addEventListener('dragleave', () => fileDropZone.classList.remove('dragover'));
  fileDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    fileDropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleScanFile(e.dataTransfer.files[0]);
  });
  scanFileInput.addEventListener('change', () => {
    if (scanFileInput.files.length) handleScanFile(scanFileInput.files[0]);
  });
}

function handleScanFile(file) {
  if (file.size > 25 * 1024 * 1024) { showToast('File exceeds the 25MB limit', 'error'); return; }
  selectedScanFile = file;
  scanFileName.textContent = file.name;
  scanFileSize.textContent = formatBytes(file.size);
  scanFileChip.style.display = 'flex';
  fileDropZone.style.display = 'none';
  scanFileBtn.disabled = false;
}

if (scanFileRemove) {
  scanFileRemove.addEventListener('click', () => {
    selectedScanFile = null;
    scanFileInput.value = '';
    scanFileChip.style.display = 'none';
    fileDropZone.style.display = 'block';
    scanFileBtn.disabled = true;
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

scanFileBtn.addEventListener('click', async () => {
  if (!selectedScanFile) { showToast('Choose a file first', 'error'); return; }

  scanFileBtn.disabled = true;
  fileProgress.classList.add('active');
  scanFileBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';

  let data;
  try {
    const formData = new FormData();
    formData.append('file', selectedScanFile);
    const res = await fetch('/api/scan-file', { method: 'POST', body: formData, credentials: 'same-origin' });
    data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Scan failed');
  } catch (err) {
    data = await localFileAnalysis(selectedScanFile);
  } finally {
    scanFileBtn.disabled = false;
    fileProgress.classList.remove('active');
    scanFileBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Scan File';
  }
  renderFileResult(data);
});

const DANGEROUS_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.jar', '.apk', '.msi', '.com', '.ps1'];
const MACRO_EXTENSIONS = ['.docm', '.xlsm', '.pptm'];

const SUSPICIOUS_SCRIPT_PATTERNS = [
  [/powershell(\.exe)?\s+.*(-enc|-e\s|-nop|-w\s+hidden|-windowstyle\s+hidden)/i, 'Obfuscated/hidden PowerShell execution'],
  [/invoke-expression|iex\s*\(/i, 'PowerShell dynamic code execution (Invoke-Expression)'],
  [/wscript\.shell|createobject\s*\(\s*["']wscript/i, 'VBScript shell automation object'],
  [/certutil.{0,20}-decode/i, 'certutil used to decode a payload (common LOLBin technique)'],
  [/downloadstring|downloadfile|net\.webclient/i, 'Script downloads remote content at runtime'],
  [/start-bitstransfer/i, 'BITS transfer used to fetch a remote file'],
  [/del\s+\/[fq]\s+.*%|rd\s+\/s\s+\/q/i, 'Forced/silent file or directory deletion'],
  [/reg\s+add.{0,40}\\run/i, 'Registry Run-key modification (common persistence technique)'],
  [/schtasks\s+\/create/i, 'Scheduled task creation (common persistence technique)'],
  [/-nop\s+-w\s+hidden|bypass\s+-c\b/i, 'Execution-policy bypass with hidden window'],
];

function looksLikeText(bytes) {
  const sample = bytes.slice(0, 4096);
  if (!sample.length) return false;
  if (sample.includes(0)) return false;
  let printable = 0;
  for (const b of sample) if ((b >= 9 && b <= 13) || (b >= 32 && b <= 126)) printable++;
  return printable / sample.length > 0.85;
}

function scanScriptContent(bytes) {
  if (!looksLikeText(bytes)) return [];
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const findings = [];
  for (const [pattern, label] of SUSPICIOUS_SCRIPT_PATTERNS) {
    if (pattern.test(text)) findings.push(label);
  }
  return findings;
}

async function sha256Hex(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function detectType(bytes, filename) {
  const sig = (start) => start.every((b, i) => bytes[i] === b);
  if (sig([0x4d, 0x5a])) return 'Windows Executable (EXE/DLL)';
  if (sig([0x7f, 0x45, 0x4c, 0x46])) return 'Linux Executable (ELF)';
  if (sig([0x50, 0x4b, 0x03, 0x04])) return 'ZIP-based Archive (ZIP/DOCX/APK/JAR)';
  if (sig([0x25, 0x50, 0x44, 0x46])) return 'PDF Document';
  if (sig([0xd0, 0xcf, 0x11, 0xe0])) return 'Legacy Office Document (DOC/XLS/PPT)';
  if (sig([0x89, 0x50, 0x4e, 0x47])) return 'PNG Image';
  if (sig([0xff, 0xd8, 0xff])) return 'JPEG Image';
  const ext = (filename.match(/\.[^.]+$/) || [''])[0].toLowerCase();
  return `Unknown (${ext || 'no extension'})`;
}

function hasDoubleExtension(filename) {
  const parts = filename.toLowerCase().split('.');
  if (parts.length >= 3) {
    const last = '.' + parts[parts.length - 1];
    const secondLast = '.' + parts[parts.length - 2];
    return DANGEROUS_EXTENSIONS.includes(last) && !DANGEROUS_EXTENSIONS.includes(secondLast);
  }
  return false;
}

async function localFileAnalysis(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer.slice(0, 8));
  const sha256 = await sha256Hex(buffer);
  const fileType = detectType(bytes, file.name);
  const ext = (file.name.match(/\.[^.]+$/) || [''])[0].toLowerCase();

  const findings = [];
  if (DANGEROUS_EXTENSIONS.includes(ext) || fileType.includes('Executable')) {
    findings.push({ severity: 'high', label: 'Executable File', detail: `This file is a native executable (${fileType}). Only run executables from sources you fully trust.` });
  }
  if (MACRO_EXTENSIONS.includes(ext)) {
    findings.push({ severity: 'high', label: 'Macro-Enabled Document', detail: `The '${ext}' extension indicates this document can run embedded macros, a common malware delivery method.` });
  }
  if (hasDoubleExtension(file.name)) {
    findings.push({ severity: 'high', label: 'Double Extension Disguise', detail: `'${file.name}' uses a double extension, a classic trick to disguise an executable as a harmless file.` });
  }
  if (file.size === 0) {
    findings.push({ severity: 'medium', label: 'Empty File', detail: 'The file has no content.' });
  }
  const scriptFindings = scanScriptContent(new Uint8Array(buffer));
  scriptFindings.forEach(label => {
    findings.push({ severity: 'high', label: 'Suspicious Script Behavior', detail: label });
  });
  if (!findings.length) {
    findings.push({ severity: 'low', label: 'No Indicators Found', detail: 'No executable signatures, macros, or naming tricks were detected in this file (client-side check — archive contents were not inspected).' });
  }

  const highCount = findings.filter(f => f.severity === 'high').length;
  const risk = highCount > 0 ? 'high' : (findings.some(f => f.severity === 'medium') ? 'medium' : 'low');
  const verdicts = { high: 'This file shows strong risk indicators', medium: 'This file has some risk indicators worth reviewing', low: 'This file appears clean based on static analysis' };

  return {
    risk_level: risk,
    verdict: verdicts[risk],
    sha256,
    metrics: [
      { label: 'File Type', value: fileType, status: fileType.includes('Unknown') ? 'warn' : 'ok' },
      { label: 'File Size', value: `${file.size.toLocaleString()} bytes`, status: 'ok' },
      { label: 'High-Severity Findings', value: String(highCount), status: highCount ? 'bad' : 'ok' },
      { label: 'Extension', value: ext || 'none', status: DANGEROUS_EXTENSIONS.includes(ext) ? 'bad' : 'ok' },
    ],
    findings,
    ai_explanation: `Static analysis of '${file.name}' (${file.size.toLocaleString()} bytes, identified as ${fileType}) found ${findings.length} indicator(s), ${highCount} of them high-severity. ${risk === 'low' ? "No signature-based red flags were found, though this client-side check can't inspect inside archives — always scan with updated antivirus software before opening unfamiliar files." : "Review the findings below before opening this file, and consider scanning it with a dedicated antivirus engine for a second opinion."}`,
  };
}

function renderFileResult(data) {
  const card = document.getElementById('resultCard');
  card.style.display = 'block';
  document.getElementById('resultVerdict').textContent = data.verdict;
  const chip = document.getElementById('riskChip');
  chip.textContent = data.risk_level.toUpperCase() + ' RISK';
  chip.className = 'risk-chip ' + data.risk_level;

  document.getElementById('sha256Value').textContent = data.sha256;

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
  data.findings.forEach(f => {
    const div = document.createElement('div');
    div.className = 'finding-item ' + f.severity;
    const icon = f.severity === 'high' ? 'fa-circle-exclamation' : f.severity === 'medium' ? 'fa-triangle-exclamation' : 'fa-circle-check';
    div.innerHTML = `<i class="fa-solid ${icon}"></i><div class="finding-body"><span class="finding-tag">${f.severity}</span><strong>${f.label}</strong><span style="font-size:12.5px;color:var(--text-dim)">${f.detail}</span></div>`;
    list.appendChild(div);
  });

  document.getElementById('aiExplanation').textContent = data.ai_explanation;
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
