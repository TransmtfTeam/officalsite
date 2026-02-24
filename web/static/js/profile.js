// profile.js: modal handling, confirm dialogs, and mobile sidebar behavior.

document.addEventListener('DOMContentLoaded', function () {
  // Generic modals.
  document.querySelectorAll('[data-modal]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var modal = document.getElementById(btn.getAttribute('data-modal'));
      if (modal) modal.classList.add('open');
    });
  });

  document.querySelectorAll('.modal-close').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var modal = btn.closest('.modal');
      if (modal) modal.classList.remove('open');
    });
  });

  document.querySelectorAll('.modal').forEach(function (modal) {
    modal.addEventListener('click', function (e) {
      if (e.target === modal) modal.classList.remove('open');
    });
  });

  if (document.getElementById('totp-pending-marker')) {
    var totpModal = document.getElementById('totp-setup-modal');
    if (totpModal) totpModal.classList.add('open');
  }

  // Themed confirm dialog.
  var cdOverlay = document.getElementById('cdialog-overlay');
  var cdIcon = document.getElementById('cdialog-icon');
  var cdTitle = document.getElementById('cdialog-title');
  var cdMsg = document.getElementById('cdialog-msg');
  var cdOK = document.getElementById('cdialog-confirm');
  var cdCancel = document.getElementById('cdialog-cancel');
  var cdCb = null;

  function showConfirm(opts) {
    if (cdIcon) cdIcon.textContent = opts.icon || '!';
    if (cdTitle) cdTitle.textContent = opts.title || 'Confirm Action';
    if (cdMsg) cdMsg.textContent = opts.msg || '';
    if (cdOK) {
      cdOK.textContent = opts.confirmLabel || 'Confirm';
      cdOK.className = 'btn ' + (opts.danger !== false ? 'btn-danger' : 'btn-primary');
    }
    cdCb = opts.onConfirm || null;
    if (cdOverlay) cdOverlay.classList.add('active');
  }

  function closeConfirm() {
    if (cdOverlay) cdOverlay.classList.remove('active');
    cdCb = null;
  }

  if (cdCancel) cdCancel.addEventListener('click', closeConfirm);
  if (cdOverlay) {
    cdOverlay.addEventListener('click', function (e) {
      if (e.target === cdOverlay) closeConfirm();
    });
  }
  if (cdOK) {
    cdOK.addEventListener('click', function () {
      var fn = cdCb;
      closeConfirm();
      if (fn) fn();
    });
  }

  // Attach confirm dialog to elements with data-confirm attribute.
  document.querySelectorAll('[data-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      showConfirm({
        icon: el.getAttribute('data-confirm-icon') || '!',
        title: el.getAttribute('data-confirm-title') || 'Confirm Action',
        msg: el.getAttribute('data-confirm') || '',
        confirmLabel: el.getAttribute('data-confirm-btn') || 'Confirm',
        onConfirm: function () {
          var form = el.form || el.closest('form');
          if (form) {
            if (el.name) {
              var prev = form.querySelector('input[data-cdialog][name="' + el.name + '"]');
              if (prev) prev.remove();
              var inp = document.createElement('input');
              inp.type = 'hidden';
              inp.name = el.name;
              inp.value = el.value || '';
              inp.setAttribute('data-cdialog', '1');
              form.appendChild(inp);
            }
            form.submit();
          } else if (el.tagName === 'A' && el.href) {
            window.location.href = el.href;
          }
        },
      });
    });
  });

  // Mobile sidebar toggle.
  var sidebarToggle = document.getElementById('sidebar-toggle');
  var sidebar = document.querySelector('.sidebar');
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

    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', function () {
        if (sidebar.classList.contains('sidebar-open')) {
          closeSidebar();
        } else {
          openSidebar();
        }
      });
    }

    if (backdrop) backdrop.addEventListener('click', closeSidebar);

    sidebar.querySelectorAll('.sidebar-link').forEach(function (link) {
      link.addEventListener('click', closeSidebar);
    });
  }
});
