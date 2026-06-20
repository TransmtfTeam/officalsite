import { Outlet } from 'react-router-dom'
import { useAuth } from '@/providers/AuthProvider'
import type { Permission } from '@/api/types'
import { Card } from '@/components/ui'

export function Forbidden() {
  return (
    <div style={{ maxWidth: 520, margin: '3rem auto', padding: '0 1rem' }}>
      <Card>
        <h2 style={{ marginTop: 0 }}>访问被拒绝</h2>
        <p style={{ color: 'var(--text2)' }}>您没有访问该页面的权限，请联系管理员。</p>
        <a className="btn btn-primary" href="/">
          返回首页
        </a>
      </Card>
    </div>
  )
}

export function RequirePermission({ perm, admin }: { perm?: Permission; admin?: boolean }) {
  const { hasPermission, isAdmin } = useAuth()
  const ok = admin ? isAdmin : perm ? hasPermission(perm) : true
  if (!ok) return <Forbidden />
  return <Outlet />
}
