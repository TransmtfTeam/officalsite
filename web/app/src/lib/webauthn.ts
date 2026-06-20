// WebAuthn / passkey helpers, ported from web/static/js/passkey.js and
// passkey-login.js. These endpoints live outside /api/v1 and authenticate via
// the X-WebAuthn-Session header + the assertion itself (no CSRF token).

function bufToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let str = ''
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i])
  return window.btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function base64urlToUint8Array(s: string): Uint8Array {
  let v = s.replace(/-/g, '+').replace(/_/g, '/')
  while (v.length % 4) v += '='
  const raw = window.atob(v)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function prepareCreationOptions(opts: any): CredentialCreationOptions {
  opts.publicKey.challenge = base64urlToUint8Array(opts.publicKey.challenge)
  opts.publicKey.user.id = base64urlToUint8Array(opts.publicKey.user.id)
  if (opts.publicKey.excludeCredentials) {
    opts.publicKey.excludeCredentials = opts.publicKey.excludeCredentials.map((c: any) => ({
      ...c,
      id: base64urlToUint8Array(c.id),
    }))
  }
  return opts
}

function prepareRequestOptions(opts: any): CredentialRequestOptions {
  opts.publicKey.challenge = base64urlToUint8Array(opts.publicKey.challenge)
  if (opts.publicKey.allowCredentials) {
    opts.publicKey.allowCredentials = opts.publicKey.allowCredentials.map((c: any) => ({
      ...c,
      id: base64urlToUint8Array(c.id),
    }))
  }
  return opts
}

function encodeCredentialCreation(cred: any) {
  return {
    id: cred.id,
    rawId: bufToBase64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToBase64url(cred.response.attestationObject),
      clientDataJSON: bufToBase64url(cred.response.clientDataJSON),
    },
  }
}

function encodeCredentialAssertion(cred: any) {
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
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */

async function getJSON(res: Response): Promise<any> {
  return res.json().catch(() => ({}))
}

export async function registerPasskey(name: string): Promise<void> {
  const beginResp = await fetch('/profile/passkey/register/begin', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  })
  const beginData = await getJSON(beginResp)
  if (!beginResp.ok) throw new Error(beginData.error || '无法开始通行密钥注册')

  const sessID = beginResp.headers.get('X-WebAuthn-Session') || ''
  const cred = (await navigator.credentials.create(prepareCreationOptions(beginData))) as any
  if (!cred) throw new Error('未创建通行密钥凭据')

  const finishResp = await fetch('/profile/passkey/register/finish?name=' + encodeURIComponent(name || '通行密钥'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-WebAuthn-Session': sessID },
    body: JSON.stringify(encodeCredentialCreation(cred)),
    credentials: 'same-origin',
  })
  const finishData = await getJSON(finishResp)
  if (!finishResp.ok) throw new Error(finishData.error || '通行密钥注册失败')
}

export async function authenticatePasskey2FA(): Promise<string | undefined> {
  const beginResp = await fetch('/login/2fa/passkey/begin', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  })
  const beginData = await getJSON(beginResp)
  if (!beginResp.ok) throw new Error(beginData.error || '无法开始通行密钥验证')

  const sessID = beginResp.headers.get('X-WebAuthn-Session') || ''
  const cred = (await navigator.credentials.get(prepareRequestOptions(beginData))) as any
  if (!cred) throw new Error('未收到通行密钥断言')

  const finishResp = await fetch('/login/2fa/passkey/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-WebAuthn-Session': sessID },
    body: JSON.stringify(encodeCredentialAssertion(cred)),
    credentials: 'same-origin',
  })
  const finishData = await getJSON(finishResp)
  if (!finishResp.ok) throw new Error(finishData.error || '通行密钥验证失败')
  return finishData.redirect as string | undefined
}

export async function primaryPasskeyLogin(next?: string, oidcChallenge?: string): Promise<string | undefined> {
  const beginResp = await fetch('/login/passkey/begin', {
    method: 'GET',
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
  })
  const beginData = await getJSON(beginResp)
  if (!beginResp.ok) throw new Error(beginData.error || '无法开始通行密钥登录')

  const sessID = beginResp.headers.get('X-WebAuthn-Session') || ''
  const cred = (await navigator.credentials.get(prepareRequestOptions(beginData))) as any
  if (!cred) throw new Error('未收到通行密钥断言')

  const params = new URLSearchParams()
  if (next) params.set('next', next)
  if (oidcChallenge) params.set('oidc_challenge', oidcChallenge)
  const qs = params.toString()
  const finishResp = await fetch('/login/passkey/finish' + (qs ? '?' + qs : ''), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-WebAuthn-Session': sessID },
    body: JSON.stringify(encodeCredentialAssertion(cred)),
    credentials: 'same-origin',
  })
  const finishData = await getJSON(finishResp)
  if (!finishResp.ok) throw new Error(finishData.error || '通行密钥登录失败')
  return (finishData.redirect as string | undefined) || '/profile'
}
