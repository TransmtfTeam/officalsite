// safeNext mirrors the server's safeNextPath: only allow same-origin relative
// paths to avoid open redirects.
export function safeNext(next: string | null | undefined, fallback: string): string {
  const n = (next ?? '').trim()
  if (!n) return fallback
  if (!n.startsWith('/') || n.startsWith('//') || /[\r\n\\]/.test(n)) return fallback
  return n
}
