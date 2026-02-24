// Primary passkey login (discoverable credentials) for /login page.
(function () {
  'use strict';

  var btn = document.getElementById('primary-passkey-login-btn');
  var msg = document.getElementById('primary-passkey-login-msg');
  if (!btn) return;

  function showError(text) {
    if (!msg) return;
    msg.textContent = text;
    msg.style.display = '';
  }

  function hideError() {
    if (!msg) return;
    msg.textContent = '';
    msg.style.display = 'none';
  }

  function base64urlToBuffer(base64url) {
    var padding = '='.repeat((4 - (base64url.length % 4)) % 4);
    var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;
    var raw = window.atob(base64);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }

  function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = '';
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return window.btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  btn.addEventListener('click', async function () {
    hideError();

    if (!window.PublicKeyCredential) {
      showError('This browser does not support passkeys.');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Verifying...';

    try {
      var beginResp = await fetch('/login/passkey/begin', {
        method: 'GET',
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
      });
      var beginData = await beginResp.json().catch(function () { return {}; });
      if (!beginResp.ok) throw new Error(beginData.error || 'Failed to start passkey login');

      var sessID = beginResp.headers.get('X-WebAuthn-Session') || '';
      var publicKey = beginData.publicKey || beginData;
      if (publicKey.challenge) publicKey.challenge = base64urlToBuffer(publicKey.challenge);
      if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map(function (c) {
          return Object.assign({}, c, { id: base64urlToBuffer(c.id) });
        });
      }

      var assertion = await navigator.credentials.get({ publicKey: publicKey });
      if (!assertion) throw new Error('No passkey assertion received');

      var payload = {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
          authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
          signature: bufferToBase64url(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
        },
      };

      var finishResp = await fetch('/login/passkey/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-WebAuthn-Session': sessID,
        },
        body: JSON.stringify(payload),
        credentials: 'same-origin',
      });
      var finishData = await finishResp.json().catch(function () { return {}; });
      if (!finishResp.ok || finishData.error) throw new Error(finishData.error || 'Passkey verification failed');

      window.location.href = finishData.redirect || '/profile';
    } catch (err) {
      if (err && err.name === 'NotAllowedError') {
        showError('Cancelled or timed out.');
      } else {
        showError((err && err.message) || 'Unexpected error.');
      }
      btn.disabled = false;
      btn.innerHTML = '<span>PK</span> Sign in with Passkey';
    }
  });
})();

