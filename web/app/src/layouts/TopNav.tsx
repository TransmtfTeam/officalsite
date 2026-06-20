import { Link, useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { useAuth } from '@/providers/AuthProvider'
import { useToast } from '@/providers/ToastProvider'

export function TopNav({ onToggleSidebar }: { onToggleSidebar?: () => void }) {
  const { user, isAdmin, isMember, settings, refresh } = useAuth()
  const navigate = useNavigate()
  const { toast } = useToast()

  const logout = async () => {
    try {
      await api.post('/logout')
    } catch {
      /* ignore */
    }
    await refresh()
    toast('已退出登录', 'success')
    navigate('/')
  }

  return (
    <nav className="nav">
      <div style={{ display: 'flex', alignItems: 'center', gap: '.6rem' }}>
        {onToggleSidebar && (
          <button className="sidebar-toggle" aria-label="打开菜单" onClick={onToggleSidebar} style={{ display: 'inline-flex' }}>
            <span className="hamburger-line" />
            <span className="hamburger-line" />
            <span className="hamburger-line" />
          </button>
        )}
        <Link className="nav-brand" to="/">
          {settings?.siteName ?? '团队站点'}
        </Link>
      </div>
      <div className="nav-links">
        {user ? (
          <>
            {isAdmin ? (
              <>
                <Link to="/member/projects">项目</Link>
                <Link to="/admin/clients">应用</Link>
                <Link to="/admin/users">用户</Link>
                <Link to="/admin">管理</Link>
              </>
            ) : isMember ? (
              <>
                <Link to="/member/projects">项目</Link>
                <Link to="/admin/clients">应用</Link>
                <Link to="/member/users">用户</Link>
              </>
            ) : null}
            <Link to="/profile">{user.displayName}</Link>
            <button type="button" className="nav-link-btn" onClick={logout}>
              退出
            </button>
          </>
        ) : (
          <>
            <Link to="/login">登录</Link>
            <Link to="/register">注册</Link>
          </>
        )}
      </div>
    </nav>
  )
}
