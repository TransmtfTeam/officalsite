// Admin 用户管理：弹窗触发、详情异步加载、二次确认删除
(function () {
  'use strict';

  function open(id) {
    var m = document.getElementById(id);
    if (m) m.classList.add('open');
  }
  function close(id) {
    var m = document.getElementById(id);
    if (m) m.classList.remove('open');
  }

  document.addEventListener('DOMContentLoaded', function () {
    // data-modal-open 触发器（与 profile.js 的 data-modal 兼容并存）
    document.querySelectorAll('[data-modal-open]').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        open(btn.getAttribute('data-modal-open'));
      });
    });

    // 用户详情按钮 -> 弹窗 + ajax
    document.querySelectorAll('[data-user-detail]').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        var id = btn.getAttribute('data-user-detail');
        var email = btn.getAttribute('data-user-email') || '';
        var name = btn.getAttribute('data-user-name') || '';
        var body = document.getElementById('user-detail-body');
        if (body) {
          body.innerHTML = '<p style="color:var(--text2);text-align:center;padding:2rem">加载中…</p>';
        }
        open('user-detail-modal');
        fetch('/admin/users/' + encodeURIComponent(id) + '?modal=1', {
          credentials: 'same-origin',
          headers: { 'Accept': 'text/html' },
        })
          .then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.text();
          })
          .then(function (html) {
            if (body) body.innerHTML = html;
            wireDeleteConfirm(email, name);
          })
          .catch(function () {
            if (body) {
              body.innerHTML =
                '<p style="color:#dc2626;text-align:center;padding:2rem">加载失败，请<a href="/admin/users/' +
                encodeURIComponent(id) +
                '">前往完整页</a>查看。</p>';
            }
          });
      });
    });
  });

  // 二次确认：用户必须输入完整邮箱才能提交删除表单
  function wireDeleteConfirm(email, name) {
    var f = document.querySelector('#user-detail-body form[data-user-delete-form]');
    if (!f) return;
    var input = f.querySelector('input[name="confirm_email"]');
    var btn = f.querySelector('button[type="submit"]');
    var hint = f.querySelector('[data-confirm-hint]');
    function refresh() {
      var ok = input && input.value.trim().toLowerCase() === (email || '').toLowerCase();
      if (btn) btn.disabled = !ok;
      if (hint) hint.style.color = ok ? '#16a34a' : '#dc2626';
    }
    if (input) {
      input.addEventListener('input', refresh);
      refresh();
    }
    f.addEventListener('submit', function (e) {
      if (input && input.value.trim().toLowerCase() !== (email || '').toLowerCase()) {
        e.preventDefault();
        alert('请输入完整邮箱以确认删除：' + email);
        return false;
      }
      if (!confirm('最终确认：删除用户 ' + (name || email) + ' ？此操作不可撤销。')) {
        e.preventDefault();
        return false;
      }
    });
  }
})();
