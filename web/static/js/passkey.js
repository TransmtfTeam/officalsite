// passkey.js — WebAuthn ceremony helpers

function bufToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToUint8Array(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function prepareCreationOptions(opts) {
  opts.publicKey.challenge = base64urlToUint8Array(opts.publicKey.challenge);
  opts.publicKey.user.id = base64urlToUint8Array(opts.publicKey.user.id);
  if (opts.publicKey.excludeCredentials) {
    opts.publicKey.excludeCredentials = opts.publicKey.excludeCredentials.map(function(c) {
      return Object.assign({}, c, { id: base64urlToUint8Array(c.id) });
    });
  }
  return opts;
}

function prepareRequestOptions(opts) {
  opts.publicKey.challenge = base64urlToUint8Array(opts.publicKey.challenge);
  if (opts.publicKey.allowCredentials) {
    opts.publicKey.allowCredentials = opts.publicKey.allowCredentials.map(function(c) {
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
      clientDataJSON: bufToBase64url(cred.response.clientDataJSON)
    }
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
      userHandle: cred.response.userHandle ? bufToBase64url(cred.response.userHandle) : null
    }
  };
}

async function registerPasskey(name) {
  var beginResp = await fetch('/profile/passkey/register/begin', {
    method: 'GET',
    headers: { 'Accept': 'application/json' }
  });
  if (!beginResp.ok) throw new Error('无法开始注册');
  var sessID = beginResp.headers.get('X-WebAuthn-Session');
  var opts = prepareCreationOptions(await beginResp.json());
  var cred = await navigator.credentials.create(opts);
  var finishResp = await fetch('/profile/passkey/register/finish?name=' + encodeURIComponent(name || 'Passkey'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-WebAuthn-Session': sessID
    },
    body: JSON.stringify(encodeCredentialCreation(cred))
  });
  if (!finishResp.ok) {
    var err = await finishResp.json();
    throw new Error(err.error || '注册失败');
  }
}

async function authenticatePasskey() {
  var beginResp = await fetch('/login/2fa/passkey/begin', {
    method: 'GET',
    headers: { 'Accept': 'application/json' }
  });
  if (!beginResp.ok) throw new Error('无法开始验证');
  var sessID = beginResp.headers.get('X-WebAuthn-Session');
  var opts = prepareRequestOptions(await beginResp.json());
  var cred = await navigator.credentials.get(opts);
  var finishResp = await fetch('/login/2fa/passkey/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-WebAuthn-Session': sessID
    },
    body: JSON.stringify(encodeCredentialAssertion(cred))
  });
  if (!finishResp.ok) {
    var err = await finishResp.json();
    throw new Error(err.error || '验证失败');
  }
  var data = await finishResp.json();
  if (data.redirect) window.location.href = data.redirect;
}

document.addEventListener('DOMContentLoaded', function() {
  // Tab switching (used on login_2fa page)
  document.querySelectorAll('.tab-btn[data-tab]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var group = btn.closest('.tab-group');
      if (!group) return;
      group.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      group.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
      btn.classList.add('active');
      var panel = group.querySelector('#' + btn.dataset.tab);
      if (panel) panel.classList.add('active');
    });
  });

  // Passkey login button
  var loginBtn = document.getElementById('passkey-login-btn');
  var loginMsg = document.getElementById('passkey-login-msg');
  if (loginBtn) {
    loginBtn.addEventListener('click', function() {
      loginBtn.disabled = true;
      loginBtn.textContent = '验证中…';
      authenticatePasskey().catch(function(e) {
        if (loginMsg) {
          loginMsg.textContent = '验证失败: ' + e.message;
          loginMsg.className = 'flash flash-err';
        }
        loginBtn.disabled = false;
        loginBtn.textContent = '使用 Passkey 验证';
      });
    });
  }

  // Passkey registration button (profile page)
  var regBtn = document.getElementById('passkey-register-btn');
  var regMsg = document.getElementById('passkey-register-msg');
  if (regBtn) {
    regBtn.addEventListener('click', function() {
      var nameInput = document.getElementById('passkey-name');
      var name = nameInput ? nameInput.value.trim() : '';
      regBtn.disabled = true;
      regBtn.textContent = '注册中…';
      registerPasskey(name).then(function() {
        if (regMsg) { regMsg.textContent = '注册成功！'; regMsg.className = 'flash flash-ok'; }
        setTimeout(function() { window.location.reload(); }, 1200);
      }).catch(function(e) {
        if (regMsg) { regMsg.textContent = '注册失败: ' + e.message; regMsg.className = 'flash flash-err'; }
        regBtn.disabled = false;
        regBtn.textContent = '注册 Passkey';
      });
    });
  }
});
