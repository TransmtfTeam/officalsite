import { Outlet, Link } from 'react-router-dom'
import { TopNav } from './TopNav'
import { AnnouncementModal } from '@/components/AnnouncementModal'
import { useAuth } from '@/providers/AuthProvider'

export function PublicLayout() {
  const { settings } = useAuth()
  return (
    <>
      <TopNav />
      <Outlet />
      <footer>
        <p>
          版权所有 © {settings?.siteName ?? '团队站点'} · 联系邮箱{' '}
          <a href={`mailto:${settings?.contactEmail ?? ''}`}>{settings?.contactEmail}</a>
        </p>
        <p style={{ marginTop: '.4rem', fontSize: '.8rem' }}>
          <Link to="/tos" style={{ color: '#666' }}>
            服务条款
          </Link>
          <span style={{ color: '#444', margin: '0 .5rem' }}>|</span>
          <Link to="/privacy" style={{ color: '#666' }}>
            隐私政策
          </Link>
        </p>
      </footer>
      <AnnouncementModal />
    </>
  )
}
