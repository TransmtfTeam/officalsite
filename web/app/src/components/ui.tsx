import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Variant = 'primary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: 'sm' | 'md'
  loading?: boolean
}

export function Button({ variant = 'primary', size = 'md', loading, disabled, className, children, ...rest }: ButtonProps) {
  const cls = [
    'btn',
    variant === 'primary' ? 'btn-primary' : variant === 'danger' ? 'btn-danger' : 'btn-ghost',
    size === 'sm' ? 'btn-sm' : '',
    className ?? '',
  ]
    .filter(Boolean)
    .join(' ')
  return (
    <button className={cls} disabled={disabled || loading} {...rest}>
      {loading && <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} aria-hidden />}
      {children}
    </button>
  )
}

export function Card({ children, className, style }: { children: ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`card${className ? ' ' + className : ''}`} style={style}>
      {children}
    </div>
  )
}

export function RoleBadge({ role, label }: { role: string; label?: string }) {
  const cls = role === 'admin' ? 'role-admin' : role === 'member' ? 'role-member' : 'role-user'
  return <span className={`role-badge ${cls}`}>{label ?? role}</span>
}

export function Spinner() {
  return <span className="spinner" role="status" aria-label="加载中" />
}

export function PageLoading() {
  return (
    <div className="app-loading">
      <Spinner />
    </div>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>
}

export function Flash({ message, error }: { message: string; error?: boolean }) {
  if (!message) return null
  return <div className={`flash ${error ? 'flash-err' : 'flash-ok'}`}>{message}</div>
}

export function StatusText({ active, on = '启用', off = '停用' }: { active: boolean; on?: string; off?: string }) {
  return <span style={{ color: active ? '#16a34a' : '#dc2626' }}>{active ? on : off}</span>
}
