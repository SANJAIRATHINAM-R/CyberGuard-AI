/* ==========================================================================
   CyberGuard AI — main.js
   Shared behaviour: loading screen, nav toggle, toasts, counters
   ========================================================================== */

// ---- Loading screen ----
window.addEventListener('load', () => {
  const loader = document.getElementById('loader');
  if (loader) {
    setTimeout(() => loader.classList.add('hide'), 500);
  }
});

// ---- Mobile nav toggle ----
const navToggle = document.getElementById('navToggle');
const navLinks = document.getElementById('navLinks');
if (navToggle && navLinks) {
  navToggle.addEventListener('click', () => navLinks.classList.toggle('open'));
  navLinks.querySelectorAll('a').forEach(a => a.addEventListener('click', () => navLinks.classList.remove('open')));
}

// ---- Toast notifications (global helper, used across all pages) ----
function showToast(message, type = 'info') {
  const stack = document.getElementById('toastStack');
  if (!stack) return;
  const icons = { success: 'fa-circle-check', error: 'fa-circle-exclamation', info: 'fa-circle-info' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span>${message}</span>`;
  stack.appendChild(toast);
  setTimeout(() => toast.remove(), 3600);
}

// ---- Animated counters for hero stats ----
function animateCounter(el, target, duration = 1400) {
  const start = 0;
  const startTime = performance.now();
  function tick(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = Math.floor(start + (target - start) * eased);
    el.textContent = value.toLocaleString();
    if (progress < 1) requestAnimationFrame(tick);
    else el.textContent = target.toLocaleString();
  }
  requestAnimationFrame(tick);
}

document.addEventListener('DOMContentLoaded', () => {
  const statScans = document.getElementById('statScans');
  const statThreats = document.getElementById('statThreats');
  if (statScans) animateCounter(statScans, 128430);
  if (statThreats) animateCounter(statThreats, 9214);
});

// ---- Contact form (landing page) ----
function handleContact(e) {
  e.preventDefault();
  showToast('Message sent — we will get back to you shortly.', 'success');
  e.target.reset();
  return false;
}

// ---- Simple fade-in-on-scroll for cards/sections ----
const revealTargets = document.querySelectorAll('.glass-card');
if ('IntersectionObserver' in window && revealTargets.length) {
  const io = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = 1;
        entry.target.style.transform = 'translateY(0)';
        io.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  revealTargets.forEach(el => {
    el.style.opacity = 0;
    el.style.transform = 'translateY(18px)';
    el.style.transition = 'opacity .6s ease, transform .6s ease';
    io.observe(el);
  });
}

// ---- AJAX helper used by all modules ----
async function apiRequest(endpoint, options = {}) {
  const base = ''; // same-origin Flask backend
  try {
    const res = await fetch(base + endpoint, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      credentials: 'same-origin',
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.message || 'Request failed');
    return data;
  } catch (err) {
    showToast(err.message || 'Network error', 'error');
    throw err;
  }
}
