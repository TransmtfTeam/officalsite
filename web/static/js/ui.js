/* ui.js — global UI helpers: toast notifications, announcement modal,
 * legal-document (ToS / Privacy) inline modals, and flash-to-toast bridging.
 *
 * Theme: minimal-white, soft animations, rounded corners.
 */
(function () {
  'use strict';

  // ──────────────────────────────────────────────────────────────
  // Toast
  // ──────────────────────────────────────────────────────────────
  function ensureStack() {
    var s = document.getElementById('toast-stack');
    if (!s) {
      s = document.createElement('div');
      s.id = 'toast-stack';
      s.className = 'toast-stack';
      s.setAttribute('aria-live', 'polite');
      document.body.appendChild(s);
    }
    return s;
  }
  /** type: 'success' | 'error' | 'info' */
  function showToast(message, type, opts) {
    if (!message) return;
    type = type || 'success';
    opts = opts || {};
    var stack = ensureStack();
    var t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.setAttribute('role', type === 'error' ? 'alert' : 'status');
    var icon = type === 'success' ? '✓' : type === 'error' ? '!' : 'i';
    t.innerHTML =
      '<span class="toast-icon">' + icon + '</span>' +
      '<span class="toast-msg"></span>' +
      '<button type="button" class="toast-close" aria-label="关闭">&times;</button>';
    t.querySelector('.toast-msg').textContent = message;
    var close = function () {
      t.classList.add('toast-leave');
      setTimeout(function () {
        if (t.parentNode) t.parentNode.removeChild(t);
      }, 280);
    };
    t.querySelector('.toast-close').addEventListener('click', close);
    stack.appendChild(t);
    // animate in
    requestAnimationFrame(function () { t.classList.add('toast-in'); });
    var ttl = typeof opts.duration === 'number' ? opts.duration : (type === 'error' ? 4500 : 2800);
    if (ttl > 0) setTimeout(close, ttl);
  }
  window.toast = showToast;

  // Bridge server-rendered .Flash into a toast and strip ?flash=… from URL.
  function bridgeServerFlash() {
    var el = document.getElementById('server-flash');
    if (el && el.dataset.msg) {
      showToast(el.dataset.msg, el.dataset.isError === '1' ? 'error' : 'success');
    }
    try {
      var u = new URL(window.location.href);
      if (u.searchParams.has('flash')) {
        u.searchParams.delete('flash');
        window.history.replaceState({}, '', u.toString());
      }
    } catch (_) { /* ignore */ }
  }

  // ──────────────────────────────────────────────────────────────
  // Generic centered modal (used for ToS / Privacy preview during
  // registration, and reusable elsewhere).
  // ──────────────────────────────────────────────────────────────
  function buildModal(title, bodyHTML) {
    var overlay = document.createElement('div');
    overlay.className = 'doc-modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.innerHTML =
      '<div class="doc-modal" role="document">' +
        '<div class="doc-modal-header">' +
          '<h3 class="doc-modal-title"></h3>' +
          '<button type="button" class="doc-modal-close" aria-label="关闭">&times;</button>' +
        '</div>' +
        '<div class="doc-modal-body"></div>' +
        '<div class="doc-modal-footer">' +
          '<button type="button" class="btn btn-primary doc-modal-ok">我已阅读</button>' +
        '</div>' +
      '</div>';
    overlay.querySelector('.doc-modal-title').textContent = title || '内容';
    overlay.querySelector('.doc-modal-body').innerHTML = bodyHTML || '<p style="color:#888">暂无内容</p>';
    var close = function () {
      overlay.classList.add('doc-modal-leaving');
      setTimeout(function () { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); }, 220);
    };
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    overlay.querySelector('.doc-modal-close').addEventListener('click', close);
    overlay.querySelector('.doc-modal-ok').addEventListener('click', close);
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); }
    });
    document.body.appendChild(overlay);
    requestAnimationFrame(function () { overlay.classList.add('doc-modal-in'); });
    return overlay;
  }
  window.openDocModal = buildModal;

  // Fetch a document (HTML fragment) from the server and show it in a modal.
  // Used for /tos and /privacy from the registration page.
  function openRemoteDoc(url, title) {
    fetch(url, { headers: { 'Accept': 'text/html' }, credentials: 'same-origin' })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        // Parse the full HTML response and extract the legal-content card.
        var doc = new DOMParser().parseFromString(html, 'text/html');
        // Find the first .card *inside* the page content (skip nav/header).
        var card = doc.querySelector('.profile-page .card') || doc.querySelector('.card');
        var body = card ? card.innerHTML : (doc.body ? doc.body.innerHTML : html);
        buildModal(title, body);
      })
      .catch(function () {
        buildModal(title, '<p style="color:#dc2626">加载失败，请稍后再试，或直接访问 <a href="' + url + '" target="_blank" rel="noopener">独立页面</a>。</p>');
      });
  }

  // Wire up [data-doc-modal] links to open the modal inline.
  function wireDocLinks() {
    document.querySelectorAll('[data-doc-modal]').forEach(function (a) {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        var url = a.getAttribute('href');
        var title = a.getAttribute('data-doc-title') || a.textContent.trim();
        openRemoteDoc(url, title);
      });
    });
  }

  // ──────────────────────────────────────────────────────────────
  // Announcement modal — once-per-revision dismiss via localStorage.
  // ──────────────────────────────────────────────────────────────
  function wireAnnModal() {
    var ov = document.getElementById('ann-modal-overlay');
    if (!ov) return;
    var key = ov.getAttribute('data-ann-key') || 'site-ann';
    try {
      if (localStorage.getItem('ann-dismiss:' + key) === '1') {
        ov.parentNode && ov.parentNode.removeChild(ov);
        return;
      }
    } catch (_) { /* ignore */ }
    var close = function () {
      ov.classList.remove('ann-modal-in');
      ov.classList.add('ann-modal-leaving');
      try { localStorage.setItem('ann-dismiss:' + key, '1'); } catch (_) {}
      setTimeout(function () { if (ov.parentNode) ov.parentNode.removeChild(ov); }, 240);
    };
    ov.querySelectorAll('[data-ann-close]').forEach(function (b) {
      b.addEventListener('click', close);
    });
    ov.addEventListener('click', function (e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); }
    });
    requestAnimationFrame(function () { ov.classList.add('ann-modal-in'); });
  }

  // ──────────────────────────────────────────────────────────────
  // Init
  // ──────────────────────────────────────────────────────────────
  function init() {
    bridgeServerFlash();
    wireDocLinks();
    wireAnnModal();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
