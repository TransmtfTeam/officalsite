import { createContext, useContext, useEffect, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, setCsrfToken } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import type { Capabilities, Me, Permission, SiteSettings, User } from '@/api/types'

interface AuthState {
  me: Me | undefined
  user: User | null
  settings: SiteSettings | undefined
  capabilities: Capabilities | undefined
  isLoading: boolean
  isAdmin: boolean
  isSystemAdmin: boolean
  isMember: boolean
  requirePasswordChange: boolean
  hasPermission: (p: Permission) => boolean
  refresh: () => Promise<unknown>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const { data: me, isLoading } = useQuery({
    queryKey: qk.me,
    queryFn: () => api.get<Me>('/me'),
    staleTime: 60_000,
  })

  useEffect(() => {
    if (me?.csrfToken) setCsrfToken(me.csrfToken)
  }, [me?.csrfToken])

  const caps = me?.capabilities
  const value: AuthState = {
    me,
    user: me?.user ?? null,
    settings: me?.settings,
    capabilities: caps,
    isLoading,
    isAdmin: !!caps?.isAdmin,
    isSystemAdmin: !!caps?.isSystemAdmin,
    isMember: !!caps?.isMember,
    requirePasswordChange: !!me?.requirePasswordChange,
    hasPermission: (p) => !!caps && (caps.isAdmin || caps.permissions.includes(p)),
    refresh: () => qc.invalidateQueries({ queryKey: qk.me }),
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
