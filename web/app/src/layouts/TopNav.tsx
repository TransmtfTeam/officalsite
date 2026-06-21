import { useState, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { api } from '@/api/client'
import { useAuth } from '@/providers/AuthProvider'
import { useToast } from '@/providers/ToastProvider'

export function TopNav({ onToggleSidebar }: { onToggleSidebar?: () => void }) {
  const { user, isAdmin, isMember, settings, refresh } = useAuth()
  const navigate = useNavigate()
  const loc = useLocation()
  const { toast } = useToast()

  // On mobile the nav links collapse into a dropdown toggled by the account
  // button on the right (a sibling to the sidebar hamburger on the left).
  const [menuOpen, setMenuOpen] = useState(false)

  // Close the dropdown on any navigation (loc.key changes per history entry,
  // covering path, search and hash changes — not just the pathname).
  useEffect(() => {
    setMenuOpen(false)
  }, [loc.key])

  // Close on Escape while the dropdown is open.
  useEffect(() => {
    if (!menuOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [menuOpen])

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

  const initial = (user?.displayName || user?.email || '?').slice(0, 1).toUpperCase()

  return (
    <nav className="nav">
      <div style={{ display: 'flex', alignItems: 'center', gap: '.6rem' }}>
        {onToggleSidebar && (
          <button
            className="sidebar-toggle"
            aria-label="打开侧边导航"
            onClick={onToggleSidebar}
            style={{ display: 'inline-flex' }}
          >
            <span className="hamburger-line" />
            <span className="hamburger-line" />
            <span className="hamburger-line" />
          </button>
        )}
        <Link className="nav-brand" to="/">
          {settings?.siteName ?? '团队站点'}
        </Link>
      </div>

      {/* Mobile-only trigger; hidden on desktop via CSS. */}
      <button
        className="nav-menu-btn"
        aria-label="导航菜单"
        aria-haspopup="menu"
        aria-expanded={menuOpen}
        aria-controls="nav-menu"
        onClick={() => setMenuOpen((v) => !v)}
      >
        {user ? (
          <span className="nav-avatar" aria-hidden>
            {initial}
          </span>
        ) : (
          <span className="nav-menu-dots" aria-hidden>
            ☰
          </span>
        )}
      </button>

      {/* Tap-outside backdrop (mobile, only while the menu is open). */}
      {menuOpen && <div className="nav-overlay" onClick={() => setMenuOpen(false)} />}

      {/* Clicking any item closes the menu (also handles same-route clicks). */}
      <div
        id="nav-menu"
        className={`nav-links${menuOpen ? ' nav-links-open' : ''}`}
        onClick={() => setMenuOpen(false)}
      >
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
