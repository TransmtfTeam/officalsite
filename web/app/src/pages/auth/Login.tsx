import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button } from '@/components/ui'
import { Input } from '@/components/form'
import { ProviderIcon } from '@/components/ProviderIcon'
import { useAuth } from '@/providers/AuthProvider'
import { useToast } from '@/providers/ToastProvider'
import { primaryPasskeyLogin } from '@/lib/webauthn'
import { safeNext } from '@/lib/nav'

interface Provider {
  slug: string
  name: string
  icon: string
}
interface ChallengeInfo {
  providerName: string
}
type LoginResult = { status: string; redirect?: string; email?: string }

export default function Login() {
  const [sp] = useSearchParams()
  const next = sp.get('next') ?? ''
  const oidcChallenge = sp.get('oidc_challenge') ?? ''
  const navigate = useNavigate()
  const { refresh } = useAuth()
  const { toast } = useToast()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [unverified, setUnverified] = useState('')
  const [loading, setLoading] = useState(false)
  const [pkLoading, setPkLoading] = useState(false)

  const { data: providers } = useQuery({
    queryKey: qk.loginProviders,
    queryFn: () => api.get<Provider[]>('/login/providers'),
  })
  const { data: challenge } = useQuery({
    queryKey: qk.oidcChallenge(oidcChallenge),
    queryFn: () => api.get<ChallengeInfo>('/login/oidc-challenge?challenge=' + encodeURIComponent(oidcChallenge)),
    enabled: !!oidcChallenge,
  })

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setUnverified('')
    setLoading(true)
    try {
      const { data } = await api.post<LoginResult>('/login', { email, password, next, oidc_challenge: oidcChallenge })
      if (data.status === 'two_factor') {
        navigate('/login/2fa')
        return
      }
      if (data.status === 'email_unverified') {
        setUnverified(data.email ?? email)
        return
      }
      await refresh()
      navigate(safeNext(data.redirect, '/profile'))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '登录失败')
    } finally {
      setLoading(false)
    }
  }

  const resend = async () => {
    try {
      const { flash } = await api.post('/verify-email/resend', { email: unverified })
      toast(flash ?? '验证邮件已发送', 'success')
    } catch {
      /* toast handled globally */
    }
  }

  const passkeyLogin = async () => {
    setError('')
    setPkLoading(true)
    try {
      const redirect = await primaryPasskeyLogin(next, oidcChallenge)
      await refresh()
      window.location.assign(redirect || '/profile')
    } catch (err) {
      const msg = err instanceof Error ? err.message : '通行密钥登录失败'
      setError(msg.includes('NotAllowed') ? '已取消或超时' : msg)
    } finally {
      setPkLoading(false)
    }
  }

  const providerHref = (slug: string) => {
    const params = new URLSearchParams()
    if (next) params.set('next', next)
    const qs = params.toString()
    return `/auth/oidc/${slug}${qs ? '?' + qs : ''}`
  }

  return (
    <AuthCard
      title="登录"
      footer={
        <>
          还没有账号？<Link to={`/register${oidcChallenge ? '?oidc_challenge=' + oidcChallenge : ''}`}>注册</Link>
          <span style={{ margin: '0 .4rem' }}>·</span>
          <Link to="/forgot-password">忘记密码？</Link>
        </>
      }
    >
      {challenge && <div className="flash flash-ok">通过 {challenge.providerName} 登录：请使用已有账号登录以完成绑定。</div>}
      {error && <div className="flash flash-err">{error}</div>}
      {unverified && (
        <div className="flash flash-err">
          邮箱尚未验证。
          <button type="button" className="nav-link-btn" style={{ textDecoration: 'underline' }} onClick={resend}>
            重新发送验证邮件
          </button>
        </div>
      )}
      <form onSubmit={submit}>
        <Input label="邮箱" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        <Input label="密码" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <Button type="submit" loading={loading} style={{ width: '100%', justifyContent: 'center' }}>
          登录
        </Button>
      </form>

      <div style={{ marginTop: '1rem' }}>
        <Button variant="ghost" onClick={passkeyLogin} loading={pkLoading} style={{ width: '100%', justifyContent: 'center' }}>
          使用通行密钥登录
        </Button>
      </div>

      {providers && providers.length > 0 && (
        <div style={{ marginTop: '1.2rem' }}>
          <div style={{ textAlign: 'center', color: 'var(--text2)', fontSize: '.82rem', margin: '.6rem 0' }}>或使用以下方式登录</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '.5rem' }}>
            {providers.map((p) => (
              <a key={p.slug} className="btn btn-ghost btn-block" href={providerHref(p.slug)} style={{ justifyContent: 'center' }}>
                <ProviderIcon slug={p.slug} icon={p.icon} />
                使用 {p.name} 登录
              </a>
            ))}
          </div>
        </div>
      )}
    </AuthCard>
  )
}
