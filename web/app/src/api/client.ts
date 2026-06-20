// Typed fetch wrapper for the JSON API. Handles the {ok,data,error,flash}
// envelope, CSRF header injection, multipart uploads and 401 redirects.

export class ApiError extends Error {
  status: number
  code: string
  fieldErrors?: Record<string, string>
  constructor(status: number, code: string, message: string, fieldErrors?: Record<string, string>) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.fieldErrors = fieldErrors
  }
}

let csrfToken = ''
export function setCsrfToken(t: string) {
  csrfToken = t || ''
}
export function getCsrfToken() {
  return csrfToken
}

type Envelope<T> = {
  ok: boolean
  data?: T
  error?: { code: string; message: string }
  fieldErrors?: Record<string, string>
  flash?: string
}

export interface ApiResult<T> {
  data: T
  flash?: string
}

const API_BASE = '/api/v1'

function loginRedirect() {
  const here = window.location.pathname + window.location.search
  if (window.location.pathname !== '/login') {
    window.location.assign('/login?next=' + encodeURIComponent(here))
  }
}

// refreshCsrf re-fetches the bootstrap endpoint to obtain a fresh CSRF token
// (e.g. after the 7-day cookie rotated). Best-effort.
async function refreshCsrf(): Promise<void> {
  try {
    const res = await fetch(API_BASE + '/me', { headers: { Accept: 'application/json' }, credentials: 'include' })
    const body = await res.json()
    const token = body?.data?.csrfToken
    if (typeof token === 'string' && token) setCsrfToken(token)
  } catch {
    /* ignore */
  }
}

async function rawRequest<T>(
  method: string,
  path: string,
  opts: { json?: unknown; form?: FormData; absolute?: boolean; retried?: boolean } = {},
): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  let body: BodyInit | undefined
  if (opts.form) {
    body = opts.form // browser sets multipart boundary
  } else if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.json)
  }
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = csrfToken
  }
  const url = opts.absolute ? path : API_BASE + path
  const res = await fetch(url, { method, headers, body, credentials: 'include' })

  if (res.status === 204) {
    return { data: undefined as T }
  }

  let parsed: Envelope<T> | null = null
  const text = await res.text()
  if (text) {
    try {
      parsed = JSON.parse(text) as Envelope<T>
    } catch {
      parsed = null
    }
  }

  if (!res.ok || (parsed && parsed.ok === false)) {
    const code = parsed?.error?.code ?? 'error'
    // One-time recovery from a rotated/expired CSRF token.
    if (res.status === 403 && code === 'csrf_failed' && !opts.retried && method !== 'GET') {
      await refreshCsrf()
      return rawRequest<T>(method, path, { ...opts, retried: true })
    }
    if (res.status === 401) {
      loginRedirect()
    }
    const message = parsed?.error?.message ?? `请求失败（${res.status}）`
    throw new ApiError(res.status, code, message, parsed?.fieldErrors)
  }

  // Unwrap envelope; tolerate bare JSON for non-enveloped endpoints.
  const data = (parsed && 'data' in parsed ? parsed.data : (parsed as unknown)) as T
  return { data, flash: parsed?.flash }
}

export const api = {
  get: <T>(path: string) => rawRequest<T>('GET', path).then((r) => r.data),
  getResult: <T>(path: string) => rawRequest<T>('GET', path),
  post: <T>(path: string, json?: unknown) => rawRequest<T>('POST', path, { json }),
  patch: <T>(path: string, json?: unknown) => rawRequest<T>('PATCH', path, { json }),
  del: <T>(path: string, json?: unknown) => rawRequest<T>('DELETE', path, { json }),
  postForm: <T>(path: string, form: FormData) => rawRequest<T>('POST', path, { form }),
  // For endpoints outside /api/v1 (e.g. /login/2fa/verify) that still use the envelope.
  postAbsolute: <T>(path: string, json?: unknown) => rawRequest<T>('POST', path, { json, absolute: true }),
  getAbsolute: <T>(path: string) => rawRequest<T>('GET', path, { absolute: true }),
}
