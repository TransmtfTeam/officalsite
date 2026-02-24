// profile.js — modal handling, confirm dialogs, and mobile sidebar

document.addEventListener('DOMContentLoaded', function() {

  // ── Generic content modals ──────────────────────────────
  document.querySelectorAll('[data-modal]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var modal = document.getElementById(btn.getAttribute('data-modal'));
      if (modal) modal.classList.add('open');
    });
  });
  document.querySelectorAll('.modal-close').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var modal = btn.closest('.modal');
      if (modal) modal.classList.remove('open');
    });
  });
  document.querySelectorAll('.modal').forEach(function(modal) {
    modal.addEventListener('click', function(e) {
      if (e.target === modal) modal.classList.remove('open');
    });
  });
  if (document.getElementById('totp-pending-marker')) {
    var totpModal = document.getElementById('totp-setup-modal');
    if (totpModal) totpModal.classList.add('open');
  }

  // ── Themed confirm dialog ───────────────────────────────
  var cdOverlay = document.getElementById('cdialog-overlay');
  var cdIcon    = document.getElementById('cdialog-icon');
  var cdTitle   = document.getElementById('cdialog-title');
  var cdMsg     = document.getElementById('cdialog-msg');
  var cdOK      = document.getElementById('cdialog-confirm');
  var cdCancel  = document.getElementById('cdialog-cancel');
  var cdCb      = null;

  function showConfirm(opts) {
    if (cdIcon)  cdIcon.textContent  = opts.icon    || '\u26a0\ufe0f';
    if (cdTitle) cdTitle.textContent = opts.title   || '确认操作';
    if (cdMsg)   cdMsg.textContent   = opts.msg     || '';
    if (cdOK) {
      cdOK.textContent = opts.confirmLabel || '确认';
      cdOK.className   = 'btn ' + (opts.danger !== false ? 'btn-danger' : 'btn-primary');
    }
    cdCb = opts.onConfirm || null;
    if (cdOverlay) cdOverlay.classList.add('active');
  }
  function closeConfirm() {
    if (cdOverlay) cdOverlay.classList.remove('active');
    cdCb = null;
  }
  if (cdCancel)  cdCancel.addEventListener('click', closeConfirm);
  if (cdOverlay) cdOverlay.addEventListener('click', function(e) {
    if (e.target === cdOverlay) closeConfirm();
  });
  if (cdOK) cdOK.addEventListener('click', function() {
    var fn = cdCb;
    closeConfirm();
    if (fn) fn();
  });

  // Attach confirm dialog to elements with data-confirm attribute.
  // <button data-confirm="message"
  //         data-confirm-title="title"
  //         data-confirm-icon="icon"
  //         data-confirm-btn="OK label">
  document.querySelectorAll('[data-confirm]').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      showConfirm({
        icon:         el.getAttribute('data-confirm-icon')  || '\u26a0\ufe0f',
        title:        el.getAttribute('data-confirm-title') || '确认操作',
        msg:          el.getAttribute('data-confirm'),
        confirmLabel: el.getAttribute('data-confirm-btn')   || '确认',
        onConfirm: function() {
          var form = el.form || el.closest('form');
          if (form) {
            if (el.name) {
              // Remove any previously added duplicate before re-appending.
              var prev = form.querySelector('input[data-cdialog][name="' + el.name + '"]');
              if (prev) prev.remove();
              var inp = document.createElement('input');
              inp.type  = 'hidden';
              inp.name  = el.name;
              inp.value = el.value || '';
              inp.setAttribute('data-cdialog', '1');
              form.appendChild(inp);
            }
            form.submit();
          } else if (el.tagName === 'A' && el.href) {
            window.location.href = el.href;
          }
        }
      });
    });
  });

  // ── Mobile sidebar toggle ──────────────────────────────
  var sidebarToggle = document.getElementById('sidebar-toggle');
  var sidebar  = document.querySelector('.sidebar');
  var backdrop = document.getElementById('sidebar-backdrop');

  if (sidebar) {
    if (sidebarToggle) sidebarToggle.style.display = 'flex';

    function openSidebar() {
      sidebar.classList.add('sidebar-open');
      if (backdrop) backdrop.classList.add('active');
      document.body.style.overflow = 'hidden';
    }
    function closeSidebar() {
      sidebar.classList.remove('sidebar-open');
      if (backdrop) backdrop.classList.remove('active');
      document.body.style.overflow = '';
    }

    if (sidebarToggle) sidebarToggle.addEventListener('click', function() {
      sidebar.classList.contains('sidebar-open') ? closeSidebar() : openSidebar();
    });
    if (backdrop) backdrop.addEventListener('click', closeSidebar);
    sidebar.querySelectorAll('.sidebar-link').forEach(function(link) {
      link.addEventListener('click', closeSidebar);
    });
  }

});
