/* ==========================================================================
   CyberGuard AI — qr.js
   QR Scanner: decode QR image client-side with jsQR, then run the decoded
   URL through the same website-scanning risk engine used by the Website
   Scanner module (backend /api/scan-website, with local JS fallback).
   ========================================================================== */

const qrDropZone = document.getElementById('qrDropZone');
const qrFileInput = document.getElementById('qrFileInput');
const qrPreview = document.getElementById('qrPreview');
const scanQrBtn = document.getElementById('scanQrBtn');
const qrProgress = document.getElementById('qrProgress');

let decodedPayload = null;

if (qrDropZone) {
  qrDropZone.addEventListener('click', () => qrFileInput.click());
  qrDropZone.addEventListener('dragover', (e) => { e.preventDefault(); qrDropZone.classList.add('dragover'); });
  qrDropZone.addEventListener('dragleave', () => qrDropZone.classList.remove('dragover'));
  qrDropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    qrDropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleQrFile(e.dataTransfer.files[0]);
  });
  qrFileInput.addEventListener('change', () => {
    if (qrFileInput.files.length) handleQrFile(qrFileInput.files[0]);
  });
}

function handleQrFile(file) {
  if (!file.type.startsWith('image/')) {
    showToast('Please upload an image file', 'error');
    return;
  }
  const reader = new FileReader();
  reader.onload = (e) => {
    qrPreview.src = e.target.result;
    qrPreview.style.display = 'block';
    decodeQrImage(e.target.result);
  };
  reader.readAsDataURL(file);
}

function decodeQrImage(dataUrl) {
  scanQrBtn.disabled = true;
  scanQrBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Decoding...';

  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = img.width;
    canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const code = window.jsQR ? jsQR(imageData.data, imageData.width, imageData.height) : null;
    scanQrBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Decode &amp; Scan';

    if (!window.jsQR) {
      decodedPayload = null;
      scanQrBtn.disabled = true;
      showToast('QR decoder library failed to load — check your internet connection', 'error');
      return;
    }

    if (code && code.data) {
      decodedPayload = code.data;
      scanQrBtn.disabled = false;
      showToast('QR code decoded successfully', 'success');
    } else {
      decodedPayload = null;
      scanQrBtn.disabled = true;
      showToast('Could not detect a QR code in this image', 'error');
    }
  };
  img.onerror = () => showToast('Could not load the image', 'error');
  img.src = dataUrl;
}

scanQrBtn.addEventListener('click', async () => {
  if (!decodedPayload) { showToast('Decode a QR image first', 'error'); return; }

  scanQrBtn.disabled = true;
  qrProgress.classList.add('active');
  scanQrBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';

  const isUrl = /^https?:\/\//i.test(decodedPayload);
  let data;

  if (isUrl) {
    try {
      data = await apiRequest('/api/scan-website', { method: 'POST', body: JSON.stringify({ url: decodedPayload }) });
    } catch (err) {
      data = localWebsiteAnalysis(decodedPayload); // defined in scanner.js, already loaded on this page
    }
    data.suggestions = data.risk_level === 'high'
      ? ['Do not visit this link or enter any information', 'Report this QR code if found in a public place']
      : data.risk_level === 'medium'
      ? ['Proceed with caution and verify the source before entering credentials']
      : ['This destination appears safe, but always double-check before entering sensitive info'];
  } else {
    // Non-URL payload (plain text, Wi-Fi config, contact card, etc.)
    data = {
      risk_level: 'low',
      verdict: 'Decoded content is not a web link',
      metrics: [
        { label: 'Payload Type', value: 'Plain text / data', status: 'ok' },
        { label: 'Length', value: `${decodedPayload.length} chars`, status: 'ok' },
      ],
      ai_explanation: 'This QR code does not encode a URL, so the standard website risk checks don\u2019t apply. Review the decoded content below and make sure it matches what you expect before acting on it.',
      suggestions: ['Read the decoded content carefully before using it', 'Be cautious if it asks you to install anything or enter credentials elsewhere'],
    };
  }

  qrProgress.classList.remove('active');
  scanQrBtn.disabled = false;
  scanQrBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i> Decode &amp; Scan';
  renderQrResult(data);
});

function renderQrResult(data) {
  const card = document.getElementById('resultCard');
  card.style.display = 'block';
  document.getElementById('resultVerdict').textContent = data.verdict;
  const chip = document.getElementById('riskChip');
  chip.textContent = data.risk_level.toUpperCase() + ' RISK';
  chip.className = 'risk-chip ' + data.risk_level;

  document.getElementById('decodedUrl').textContent = decodedPayload;

  const grid = document.getElementById('metricGrid');
  grid.innerHTML = '';
  (data.metrics || []).forEach(m => {
    const div = document.createElement('div');
    div.className = 'metric ' + m.status;
    div.innerHTML = `<span>${m.label}</span><strong>${m.value}</strong>`;
    grid.appendChild(div);
  });

  document.getElementById('aiExplanation').textContent = data.ai_explanation;

  const list = document.getElementById('suggestionList');
  list.innerHTML = '';
  (data.suggestions || []).forEach(s => {
    const li = document.createElement('li');
    li.textContent = s;
    list.appendChild(li);
  });

  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
