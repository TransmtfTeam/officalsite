import { NavLink, useLocation } from 'react-router-dom'
import { useAuth } from '@/providers/AuthProvider'
import type { Permission } from '@/api/types'

interface Item {
  to: string
  label: string
  perm?: Permission | 'admin'
}

const ADMIN_ITEMS: Item[] = [
  { to: '/admin', label: '概览', perm: 'admin' },
  { to: '/admin/users', label: '用户', perm: 'manage_users' },
  { to: '/admin/groups', label: '分组', perm: 'manage_groups' },
  { to: '/admin/clients', label: '应用', perm: 'manage_clients' },
  { to: '/admin/providers', label: '登录方式', perm: 'manage_providers' },
  { to: '/admin/roles', label: '角色', perm: 'manage_roles' },
  { to: '/admin/announcements', label: '公告', perm: 'manage_announcements' },
  { to: '/admin/settings', label: '设置', perm: 'manage_settings' },
  { to: '/admin/audit-logs', label: '审计日志', perm: 'admin' },
]

const MEMBER_ITEMS: Item[] = [
  { to: '/member/projects', label: '项目管理', perm: 'manage_projects' },
  { to: '/member/links', label: '友情链接', perm: 'manage_projects' },
  { to: '/member/users', label: '用户管理', perm: 'view_users' },
]

export function Sidebar({ onNavigate, open }: { onNavigate?: () => void; open?: boolean }) {
  const { isAdmin, hasPermission } = useAuth()
  const loc = useLocation()
  const section = loc.pathname.startsWith('/admin') ? 'admin' : loc.pathname.startsWith('/member') ? 'member' : isAdmin ? 'admin' : 'member'

  const canSee = (it: Item) => {
    if (!it.perm) return true
    if (it.perm === 'admin') return isAdmin
    return hasPermission(it.perm)
  }
  const items = (section === 'admin' ? ADMIN_ITEMS : MEMBER_ITEMS).filter(canSee)

  return (
    <aside className={`sidebar${open ? ' sidebar-open' : ''}`}>
      <div className="sidebar-section">
        <div className="sidebar-title">{section === 'admin' ? '管理导航' : '成员导航'}</div>
        {items.map((it) => (
          <NavLink
            key={it.to}
            to={it.to}
            end={it.to === '/admin'}
            className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
            onClick={onNavigate}
          >
            {it.label}
          </NavLink>
        ))}
      </div>
      <div className="sidebar-section">
        <div className="sidebar-title">快速入口</div>
        <NavLink className="sidebar-link" to="/" onClick={onNavigate}>
          返回首页
        </NavLink>
        <NavLink className="sidebar-link" to="/profile" onClick={onNavigate}>
          个人资料
        </NavLink>
        <NavLink className="sidebar-link" to="/member/projects" onClick={onNavigate}>
          社区项目
        </NavLink>
      </div>
    </aside>
  )
}
