import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '@/providers/AuthProvider'
import { PageLoading } from '@/components/ui'

export function RequireAuth() {
  const { user, isLoading, requirePasswordChange } = useAuth()
  const loc = useLocation()

  if (isLoading) return <PageLoading />
  if (!user) {
    return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  }
  if (requirePasswordChange && loc.pathname !== '/profile/change-password') {
    return <Navigate to="/profile/change-password" replace />
  }
  return <Outlet />
}
