import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button, PageLoading } from '@/components/ui'
import { Input } from '@/components/form'
import { useAuth } from '@/providers/AuthProvider'
import { authenticatePasskey2FA } from '@/lib/webauthn'
import { safeNext } from '@/lib/nav'

interface Status {
  status?: string
  redirect?: string
  email?: string
  hasTOTP?: boolean
  hasPasskey?: boolean
}

export default function Login2FA() {
  const navigate = useNavigate()
  const { refresh } = useAuth()
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [pkLoading, setPkLoading] = useState(false)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['login-2fa-status'],
    queryFn: () => api.getAbsolute<Status>('/login/2fa/status').then((r) => r.data),
    retry: false,
  })

  if (isLoading) return <PageLoading />
  if (isError || !data) {
    return (
      <AuthCard title="双重验证">
        <div className="flash flash-err">登录会话已过期，请重新登录。</div>
        <Button onClick={() => navigate('/login')} style={{ width: '100%', justifyContent: 'center' }}>
          返回登录
        </Button>
      </AuthCard>
    )
  }
  if (data.status === 'already_authenticated') {
    navigate(safeNext(data.redirect, '/profile'))
    return <PageLoading />
  }

  const verify = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data: res } = await api.postAbsolute<{ redirect?: string }>('/login/2fa/verify', { totp_code: code })
      await refresh()
      navigate(safeNext(res.redirect, '/profile'))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '验证失败')
    } finally {
      setLoading(false)
    }
  }

  const passkey = async () => {
    setError('')
    setPkLoading(true)
    try {
      const redirect = await authenticatePasskey2FA()
      await refresh()
      window.location.assign(redirect || '/profile')
    } catch (err) {
      const msg = err instanceof Error ? err.message : '通行密钥验证失败'
      setError(msg.includes('NotAllowed') ? '已取消或超时' : msg)
    } finally {
      setPkLoading(false)
    }
  }

  return (
    <AuthCard title="双重验证">
      <p style={{ color: 'var(--text2)', fontSize: '.9rem', marginTop: 0 }}>账号 {data.email} 已启用双重验证。</p>
      {error && <div className="flash flash-err">{error}</div>}
      {data.hasTOTP && (
        <form onSubmit={verify}>
          <Input
            label="动态口令验证码"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            autoFocus
          />
          <Button type="submit" loading={loading} style={{ width: '100%', justifyContent: 'center' }}>
            验证
          </Button>
        </form>
      )}
      {data.hasPasskey && (
        <div style={{ marginTop: '1rem' }}>
          <Button variant="ghost" onClick={passkey} loading={pkLoading} style={{ width: '100%', justifyContent: 'center' }}>
            使用通行密钥
          </Button>
        </div>
      )}
    </AuthCard>
  )
}
