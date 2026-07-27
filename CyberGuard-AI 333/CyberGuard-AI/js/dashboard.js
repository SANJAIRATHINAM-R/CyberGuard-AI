/* ==========================================================================
   CyberGuard AI — dashboard.js
   Chart.js visualizations, sidebar toggle, table filtering, security ring
   ========================================================================== */

// ---- Sidebar toggle (mobile) ----
const sideToggle = document.getElementById('sideToggle');
const sidebar = document.getElementById('sidebar');
if (sideToggle && sidebar) {
  sideToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
}

// ---- Dark mode toggle (this app is dark-first; toggle switches to a dimmer variant) ----
const darkToggle = document.getElementById('darkToggle');
if (darkToggle) {
  darkToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-mode');
    const icon = darkToggle.querySelector('i');
    icon.classList.toggle('fa-moon');
    icon.classList.toggle('fa-sun');
    showToast('Theme preference updated', 'info');
  });
}

// ---- Security score ring animation ----
document.addEventListener('DOMContentLoaded', () => {
  const ring = document.querySelector('.kpi-ring');
  if (ring) {
    const score = parseInt(ring.dataset.score, 10) || 0;
    const circle = ring.querySelector('.ring-fg');
    const circumference = 264;
    const offset = circumference - (score / 100) * circumference;
    setTimeout(() => { circle.style.strokeDashoffset = offset; }, 200);
  }

  // KPI count-up
  const scans = document.getElementById('kpiScans');
  const threats = document.getElementById('kpiThreats');
  const files = document.getElementById('kpiFiles');
  if (scans) animateCounter(scans, 47, 900);
  if (threats) animateCounter(threats, 6, 900);
  if (files) animateCounter(files, 132, 900);
});

// ---- Chart.js global defaults for dark theme ----
if (window.Chart) {
  Chart.defaults.color = '#7686a0';
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
}

// ---- Threat Timeline (line chart) ----
const timelineCtx = document.getElementById('timelineChart');
if (timelineCtx) {
  new Chart(timelineCtx, {
    type: 'line',
    data: {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      datasets: [
        {
          label: 'Threats Detected',
          data: [12, 19, 8, 24, 15, 6, 11],
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0,212,255,0.12)',
          tension: 0.4, fill: true, pointRadius: 3, pointBackgroundColor: '#00d4ff',
        },
        {
          label: 'Scans Run',
          data: [40, 52, 38, 61, 47, 25, 33],
          borderColor: '#8b6bff',
          backgroundColor: 'rgba(139,107,255,0.08)',
          tension: 0.4, fill: true, pointRadius: 3, pointBackgroundColor: '#8b6bff',
        }
      ]
    },
    options: {
      responsive: true,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true } } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
      }
    }
  });
}

// ---- Risk Breakdown (pie/doughnut) ----
const pieCtx = document.getElementById('riskPie');
if (pieCtx) {
  new Chart(pieCtx, {
    type: 'doughnut',
    data: {
      labels: ['Low Risk', 'Medium Risk', 'High Risk'],
      datasets: [{
        data: [64, 24, 12],
        backgroundColor: ['#2ee6a6', '#ffb84d', '#ff4d6d'],
        borderColor: '#0c1220',
        borderWidth: 3,
      }]
    },
    options: {
      responsive: true,
      cutout: '68%',
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true } } }
    }
  });
}

// ---- Attack Categories (bar chart) ----
const catCtx = document.getElementById('categoryChart');
if (catCtx) {
  new Chart(catCtx, {
    type: 'bar',
    data: {
      labels: ['Phishing', 'Malware', 'Brute Force', 'SQLi', 'XSS', 'Spoofing'],
      datasets: [{
        label: 'Incidents',
        data: [34, 21, 18, 12, 9, 15],
        backgroundColor: ['#00d4ff', '#2f8bff', '#8b6bff', '#ff4d6d', '#ffb84d', '#2ee6a6'],
        borderRadius: 8,
        maxBarThickness: 42,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
      }
    }
  });
}

// ---- Activity table filter/search ----
const tableFilter = document.getElementById('tableFilter');
const globalSearch = document.getElementById('globalSearch');

function filterTable(query) {
  const rows = document.querySelectorAll('#activityTable tbody tr');
  const q = query.trim().toLowerCase();
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
if (tableFilter) tableFilter.addEventListener('input', (e) => filterTable(e.target.value));
if (globalSearch) globalSearch.addEventListener('input', (e) => filterTable(e.target.value));
