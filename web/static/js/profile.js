// 个人资料页脚本：弹窗、确认框与移动端侧栏行为。

document.addEventListener('DOMContentLoaded', function () {
  // 通用弹窗。
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

  // 主题确认弹窗。
  var cdOverlay = document.getElementById('cdialog-overlay');
  var cdIcon = document.getElementById('cdialog-icon');
  var cdTitle = document.getElementById('cdialog-title');
  var cdMsg = document.getElementById('cdialog-msg');
  var cdOK = document.getElementById('cdialog-confirm');
  var cdCancel = document.getElementById('cdialog-cancel');
  var cdCb = null;

  function show确认(opts) {
    if (cdIcon) cdIcon.textContent = opts.icon || '!';
    if (cdTitle) cdTitle.textContent = opts.title || '确认操作';
    if (cdMsg) cdMsg.textContent = opts.msg || '';
    if (cdOK) {
      cdOK.textContent = opts.confirmLabel || '确认';
      cdOK.className = 'btn ' + (opts.danger !== false ? 'btn-danger' : 'btn-primary');
    }
    cdCb = opts.on确认 || null;
    if (cdOverlay) cdOverlay.classList.add('active');
  }

  function close确认() {
    if (cdOverlay) cdOverlay.classList.remove('active');
    cdCb = null;
  }

  if (cdCancel) cdCancel.addEventListener('click', close确认);
  if (cdOverlay) {
    cdOverlay.addEventListener('click', function (e) {
      if (e.target === cdOverlay) close确认();
    });
  }
  if (cdOK) {
    cdOK.addEventListener('click', function () {
      var fn = cdCb;
      close确认();
      if (fn) fn();
    });
  }

  // 给带有 data-confirm 的元素绑定确认弹窗。
  document.querySelectorAll('[data-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      show确认({
        icon: el.getAttribute('data-confirm-icon') || '!',
        title: el.getAttribute('data-confirm-title') || '确认操作',
        msg: el.getAttribute('data-confirm') || '',
        confirmLabel: el.getAttribute('data-confirm-btn') || '确认',
        on确认: function () {
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

  // 移动端侧栏开关。
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
