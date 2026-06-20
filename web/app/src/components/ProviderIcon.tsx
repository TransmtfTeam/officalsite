// Built-in SVG icons for known external providers, ported from main.go.
export function ProviderIcon({ slug, icon }: { slug?: string; icon?: string }) {
  const key = (slug || icon || '').toLowerCase().trim()
  if (key === 'google') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true" width="18" height="18">
        <path fill="#EA4335" d="M12 10.2v3.9h5.5c-.3 1.5-1.8 4.3-5.5 4.3-3.3 0-6-2.7-6-6.1s2.7-6.1 6-6.1c1.9 0 3.2.8 3.9 1.5l2.7-2.6C17 3.6 14.8 2.6 12 2.6a9.4 9.4 0 0 0 0 18.8c5.4 0 9-3.8 9-9.1 0-.6-.1-1.2-.2-2H12z" />
        <path fill="#4285F4" d="M3.5 7.6l3.2 2.3A6 6 0 0 1 12 6.2c1.9 0 3.2.8 3.9 1.5l2.7-2.6C17 3.6 14.8 2.6 12 2.6a9.4 9.4 0 0 0-8.5 5z" />
        <path fill="#FBBC05" d="M12 21.4c2.7 0 4.9-.9 6.5-2.5l-3-2.4c-.8.6-2 1-3.5 1-3.6 0-5.2-2.7-5.5-4.2l-3.2 2.4a9.4 9.4 0 0 0 8.7 5.7z" />
        <path fill="#34A853" d="M3.3 15.7l3.2-2.4c-.2-.6-.4-1.1-.4-1.8s.1-1.2.4-1.8L3.3 7.3A9.4 9.4 0 0 0 2.6 12c0 1.4.3 2.7.7 3.7z" />
      </svg>
    )
  }
  if (key === 'x' || key === 'x.com' || key === 'xcom' || key === 'twitter') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true" width="18" height="18">
        <rect x="1" y="1" width="22" height="22" rx="5" fill="#111827" />
        <path d="M7 6.5h2.8l3.1 4.3 3.6-4.3h2.7l-5.2 6.1 5.5 7h-2.8l-3.5-4.6-4 4.6H6.5l5.7-6.6L7 6.5zm3.2 1.7H9l6 9.7h1.2l-6-9.7z" fill="#fff" />
      </svg>
    )
  }
  return null
}
