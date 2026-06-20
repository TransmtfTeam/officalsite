import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { PageLoading, EmptyState } from '@/components/ui'
import { useAuth } from '@/providers/AuthProvider'
import type { Permission } from '@/api/types'

interface DashboardStats {
  users: number
  clients: number
  projects: number
  providers: number
}

interface StatDef {
  key: keyof DashboardStats
  label: string
  to: string
  perm?: Permission | 'admin'
}

const STATS: StatDef[] = [
  { key: 'users', label: '用户', to: '/admin/users', perm: 'manage_users' },
  { key: 'clients', label: '应用', to: '/admin/clients', perm: 'manage_clients' },
  { key: 'projects', label: '项目', to: '/member/projects', perm: 'manage_projects' },
  { key: 'providers', label: '登录方式', to: '/admin/providers', perm: 'manage_providers' },
]

interface QuickLink {
  to: string
  label: string
  perm?: Permission | 'admin'
}

const QUICK_LINKS: QuickLink[] = [
  { to: '/admin/users', label: '用户管理', perm: 'manage_users' },
  { to: '/admin/groups', label: '分组管理', perm: 'manage_groups' },
  { to: '/admin/clients', label: '应用管理', perm: 'manage_clients' },
  { to: '/admin/providers', label: '登录方式', perm: 'manage_providers' },
  { to: '/admin/roles', label: '角色管理', perm: 'manage_roles' },
  { to: '/admin/announcements', label: '公告管理', perm: 'manage_announcements' },
  { to: '/admin/settings', label: '站点设置', perm: 'manage_settings' },
  { to: '/admin/audit-logs', label: '审计日志', perm: 'admin' },
]

export default function Dashboard() {
  const { isAdmin, hasPermission } = useAuth()
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.dashboard,
    queryFn: () => api.get<DashboardStats>('/admin/dashboard'),
  })

  const canSee = (perm?: Permission | 'admin') => {
    if (!perm) return true
    if (perm === 'admin') return isAdmin
    return hasPermission(perm)
  }

  if (isLoading) return <PageLoading />

  return (
    <>
      <h1 className="panel-title">管理概览</h1>
      <p className="panel-sub">站点核心数据一览与常用管理入口。</p>

      {isError ? (
        <EmptyState>加载统计数据失败，请稍后重试</EmptyState>
      ) : (
        <div className="stats-row">
          {STATS.filter((s) => canSee(s.perm)).map((s) => {
            const num = data?.[s.key] ?? 0
            const card = (
              <div className="stat-card">
                <div className="stat-num">{num}</div>
                <div className="stat-label">{s.label}</div>
              </div>
            )
            return canSee(s.perm) && s.to ? (
              <Link key={s.key} to={s.to} style={{ textDecoration: 'none' }}>
                {card}
              </Link>
            ) : (
              <div key={s.key}>{card}</div>
            )
          })}
        </div>
      )}

      <div className="card">
        <h2 className="form-panel-title">快速入口</h2>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
            gap: '.75rem',
          }}
        >
          {QUICK_LINKS.filter((l) => canSee(l.perm)).map((l) => (
            <Link
              key={l.to}
              to={l.to}
              className="btn btn-ghost"
              style={{ justifyContent: 'center', textAlign: 'center' }}
            >
              {l.label}
            </Link>
          ))}
        </div>
      </div>
    </>
  )
}
