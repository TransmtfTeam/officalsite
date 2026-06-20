import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button } from '@/components/ui'
import { Input } from '@/components/form'
import { useAuth } from '@/providers/AuthProvider'

export default function VerifyEmail() {
  const [sp] = useSearchParams()
  const token = sp.get('token') ?? ''
  const statusParam = sp.get('status') ?? ''
  const emailParam = sp.get('email') ?? ''
  const navigate = useNavigate()
  const { user, refresh } = useAuth()

  const [verified, setVerified] = useState(false)
  const [error, setError] = useState('')
  const [email, setEmail] = useState(emailParam)
  const [resendMsg, setResendMsg] = useState('')
  const ran = useRef(false)

  useEffect(() => {
    if (!token || ran.current) return
    ran.current = true
    if (user) {
      setError('请先退出登录再验证新账号邮箱')
      return
    }
    api
      .post<{ verified: boolean; autoLoggedIn: boolean }>('/verify-email', { token })
      .then(async ({ data }) => {
        setVerified(true)
        if (data.autoLoggedIn) {
          await refresh()
          setTimeout(() => navigate('/profile'), 1200)
        }
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : '验证链接无效或已过期'))
  }, [token, user, refresh, navigate])

  const resend = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const { flash } = await api.post('/verify-email/resend', { email })
      setResendMsg(flash ?? '验证邮件已重新发送，请查收。')
    } catch {
      /* toast handled */
    }
  }

  const statusMsg: Record<string, string> = {
    sent: '注册成功！请查收验证邮件。',
    resent: '如果该邮箱已注册且未验证，验证邮件已重新发送，请查收。',
    init_failed: '注册成功，但验证邮件初始化失败，请重新发送。',
  }

  return (
    <AuthCard title="验证邮箱" footer={<Link to="/login">返回登录</Link>}>
      {verified && <div className="flash flash-ok">邮箱验证成功，欢迎加入！</div>}
      {error && <div className="flash flash-err">{error}</div>}
      {!token && statusParam && statusMsg[statusParam] && (
        <div className={`flash ${statusParam === 'init_failed' ? 'flash-err' : 'flash-ok'}`}>{statusMsg[statusParam]}</div>
      )}
      {resendMsg && <div className="flash flash-ok">{resendMsg}</div>}

      {!verified && !token && (
        <form onSubmit={resend}>
          <p style={{ color: 'var(--text2)', fontSize: '.9rem' }}>没有收到验证邮件？输入邮箱重新发送。</p>
          <Input label="邮箱" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <Button type="submit" style={{ width: '100%', justifyContent: 'center' }}>
            重新发送验证邮件
          </Button>
        </form>
      )}
    </AuthCard>
  )
}
