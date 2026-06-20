import { Outlet, Link } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from '@/providers/AuthProvider'

export function AuthLayout() {
  return (
    <div className="auth-page">
      <Outlet />
    </div>
  )
}

// AuthCard is the standard centered card used by every auth page.
export function AuthCard({ title, children, footer }: { title: string; children: ReactNode; footer?: ReactNode }) {
  const { settings } = useAuth()
  return (
    <div className="auth-card">
      <div className="auth-logo">
        <Link to="/" className="auth-logo-text">
          {settings?.siteName ?? '团队站点'}
        </Link>
      </div>
      <h1 className="auth-title">{title}</h1>
      {children}
      {footer && <div className="auth-footer-link">{footer}</div>}
    </div>
  )
}
