// 通行密钥辅助脚本：用于个人资料页注册和双重验证页校验。
(function () {
  'use strict';

  function bufToBase64url(buf) {
    var bytes = new Uint8Array(buf);
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return window.btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64urlToUint8Array(s) {
    var v = s.replace(/-/g, '+').replace(/_/g, '/');
    while (v.length % 4) v += '=';
    var raw = window.atob(v);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function prepareCreationOptions(opts) {
    opts.publicKey.challenge = base64urlToUint8Array(opts.publicKey.challenge);
    opts.publicKey.user.id = base64urlToUint8Array(opts.publicKey.user.id);
    if (opts.publicKey.excludeCredentials) {
      opts.publicKey.excludeCredentials = opts.publicKey.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: base64urlToUint8Array(c.id) });
      });
    }
    return opts;
  }

  function prepareRequestOptions(opts) {
    opts.publicKey.challenge = base64urlToUint8Array(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials) {
      opts.publicKey.allowCredentials = opts.publicKey.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: base64urlToUint8Array(c.id) });
      });
    }
    return opts;
  }

  function encodeCredentialCreation(cred) {
    return {
      id: cred.id,
      rawId: bufToBase64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToBase64url(cred.response.attestationObject),
        clientDataJSON: bufToBase64url(cred.response.clientDataJSON),
      },
    };
  }

  function encodeCredentialAssertion(cred) {
    return {
      id: cred.id,
      rawId: bufToBase64url(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToBase64url(cred.response.authenticatorData),
        clientDataJSON: bufToBase64url(cred.response.clientDataJSON),
        signature: bufToBase64url(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToBase64url(cred.response.userHandle) : null,
      },
    };
  }

  async function registerPasskey(name) {
    var beginResp = await fetch('/profile/passkey/register/begin', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
    });
    var beginData = await beginResp.json().catch(function () { return {}; });
    if (!beginResp.ok) throw new Error(beginData.error || '无法开始通行密钥注册');

    var sessID = beginResp.headers.get('X-WebAuthn-Session') || '';
    var opts = prepareCreationOptions(beginData);
    var cred = await navigator.credentials.create(opts);
    if (!cred) throw new Error('未创建通行密钥凭据');

    var finishResp = await fetch('/profile/passkey/register/finish?name=' + encodeURIComponent(name || '通行密钥'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WebAuthn-Session': sessID,
      },
      body: JSON.stringify(encodeCredentialCreation(cred)),
      credentials: 'same-origin',
    });
    var finishData = await finishResp.json().catch(function () { return {}; });
    if (!finishResp.ok) throw new Error(finishData.error || '通行密钥注册失败');
  }

  async function authenticatePasskey2FA() {
    var beginResp = await fetch('/login/2fa/passkey/begin', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
    });
    var beginData = await beginResp.json().catch(function () { return {}; });
    if (!beginResp.ok) throw new Error(beginData.error || '无法开始通行密钥验证');

    var sessID = beginResp.headers.get('X-WebAuthn-Session') || '';
    var opts = prepareRequestOptions(beginData);
    var cred = await navigator.credentials.get(opts);
    if (!cred) throw new Error('未收到通行密钥断言');

    var finishResp = await fetch('/login/2fa/passkey/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WebAuthn-Session': sessID,
      },
      body: JSON.stringify(encodeCredentialAssertion(cred)),
      credentials: 'same-origin',
    });
    var finishData = await finishResp.json().catch(function () { return {}; });
    if (!finishResp.ok) throw new Error(finishData.error || '通行密钥验证失败');

    if (finishData.redirect) window.location.href = finishData.redirect;
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.tab-btn[data-tab]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var group = btn.closest('.tab-group');
        if (!group) return;
        group.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.remove('active'); });
        group.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.remove('active'); });
        btn.classList.add('active');
        var panel = group.querySelector('#' + btn.dataset.tab);
        if (panel) panel.classList.add('active');
      });
    });

    // 双重验证页的通行密钥登录按钮（仅 /login/2fa 使用）。
    var path = window.location.pathname || '';
    var loginBtn = document.getElementById('passkey-login-btn');
    var loginMsg = document.getElementById('passkey-login-msg');
    if (loginBtn && path.indexOf('/login/2fa') === 0) {
      loginBtn.addEventListener('click', function () {
        loginBtn.disabled = true;
        loginBtn.textContent = '验证中...';
        authenticatePasskey2FA().catch(function (e) {
          if (loginMsg) {
            loginMsg.textContent = '通行密钥验证失败：' + e.message;
            loginMsg.className = 'flash flash-err';
          }
          loginBtn.disabled = false;
          loginBtn.textContent = '使用通行密钥';
        });
      });
    }

    // 个人资料页通行密钥注册按钮。
    var regBtn = document.getElementById('passkey-register-btn');
    var regMsg = document.getElementById('passkey-register-msg');
    if (regBtn) {
      regBtn.addEventListener('click', function () {
        var nameInput = document.getElementById('passkey-name');
        var name = nameInput ? nameInput.value.trim() : '';
        regBtn.disabled = true;
        regBtn.textContent = '注册中...';
        registerPasskey(name).then(function () {
          if (regMsg) {
            regMsg.textContent = '通行密钥注册成功。';
            regMsg.className = 'flash flash-ok';
          }
          window.setTimeout(function () { window.location.reload(); }, 1200);
        }).catch(function (e) {
          if (regMsg) {
            regMsg.textContent = '通行密钥注册失败：' + e.message;
            regMsg.className = 'flash flash-err';
          }
          regBtn.disabled = false;
          regBtn.textContent = '注册通行密钥';
        });
      });
    }
  });
})();
