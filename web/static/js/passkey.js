// WebAuthn helper for passkey registration (profile) and 2FA passkey step.
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
    if (!beginResp.ok) throw new Error(beginData.error || 'Unable to start passkey registration');

    var sessID = beginResp.headers.get('X-WebAuthn-Session') || '';
    var opts = prepareCreationOptions(beginData);
    var cred = await navigator.credentials.create(opts);
    if (!cred) throw new Error('No passkey credential created');

    var finishResp = await fetch('/profile/passkey/register/finish?name=' + encodeURIComponent(name || 'Passkey'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WebAuthn-Session': sessID,
      },
      body: JSON.stringify(encodeCredentialCreation(cred)),
      credentials: 'same-origin',
    });
    var finishData = await finishResp.json().catch(function () { return {}; });
    if (!finishResp.ok) throw new Error(finishData.error || 'Passkey registration failed');
  }

  async function authenticatePasskey2FA() {
    var beginResp = await fetch('/login/2fa/passkey/begin', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
    });
    var beginData = await beginResp.json().catch(function () { return {}; });
    if (!beginResp.ok) throw new Error(beginData.error || 'Unable to start passkey verification');

    var sessID = beginResp.headers.get('X-WebAuthn-Session') || '';
    var opts = prepareRequestOptions(beginData);
    var cred = await navigator.credentials.get(opts);
    if (!cred) throw new Error('No passkey assertion received');

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
    if (!finishResp.ok) throw new Error(finishData.error || 'Passkey verification failed');

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

    // 2FA passkey login button (only on /login/2fa)
    var path = window.location.pathname || '';
    var loginBtn = document.getElementById('passkey-login-btn');
    var loginMsg = document.getElementById('passkey-login-msg');
    if (loginBtn && path.indexOf('/login/2fa') === 0) {
      loginBtn.addEventListener('click', function () {
        loginBtn.disabled = true;
        loginBtn.textContent = 'Verifying...';
        authenticatePasskey2FA().catch(function (e) {
          if (loginMsg) {
            loginMsg.textContent = 'Passkey verification failed: ' + e.message;
            loginMsg.className = 'flash flash-err';
          }
          loginBtn.disabled = false;
          loginBtn.textContent = 'Use Passkey';
        });
      });
    }

    // Profile passkey registration button.
    var regBtn = document.getElementById('passkey-register-btn');
    var regMsg = document.getElementById('passkey-register-msg');
    if (regBtn) {
      regBtn.addEventListener('click', function () {
        var nameInput = document.getElementById('passkey-name');
        var name = nameInput ? nameInput.value.trim() : '';
        regBtn.disabled = true;
        regBtn.textContent = 'Registering...';
        registerPasskey(name).then(function () {
          if (regMsg) {
            regMsg.textContent = 'Passkey registered successfully.';
            regMsg.className = 'flash flash-ok';
          }
          window.setTimeout(function () { window.location.reload(); }, 1200);
        }).catch(function (e) {
          if (regMsg) {
            regMsg.textContent = 'Passkey registration failed: ' + e.message;
            regMsg.className = 'flash flash-err';
          }
          regBtn.disabled = false;
          regBtn.textContent = 'Register Passkey';
        });
      });
    }
  });
})();
