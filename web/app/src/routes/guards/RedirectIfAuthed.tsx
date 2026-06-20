import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '@/providers/AuthProvider'
import { PageLoading } from '@/components/ui'
import { safeNext } from '@/lib/nav'

// For /login and /register: if already authenticated, bounce to next/profile.
export function RedirectIfAuthed() {
  const { user, isLoading } = useAuth()
  const loc = useLocation()
  if (isLoading) return <PageLoading />
  if (user) {
    const params = new URLSearchParams(loc.search)
    return <Navigate to={safeNext(params.get('next'), '/profile')} replace />
  }
  return <Outlet />
}
