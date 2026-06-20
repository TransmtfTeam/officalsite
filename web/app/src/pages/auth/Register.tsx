import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button } from '@/components/ui'
import { Input } from '@/components/form'
import { DocModal } from '@/components/DocModal'

interface Challenge {
  providerName: string
  profileName: string
  profileEmail: string
}

export default function Register() {
  const [sp] = useSearchParams()
  const next = sp.get('next') ?? ''
  const oidcChallenge = sp.get('oidc_challenge') ?? ''
  const navigate = useNavigate()

  const { data: challenge } = useQuery({
    queryKey: qk.oidcChallenge(oidcChallenge),
    queryFn: () => api.get<Challenge>('/login/oidc-challenge?challenge=' + encodeURIComponent(oidcChallenge)),
    enabled: !!oidcChallenge,
  })

  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [agree, setAgree] = useState(false)
  const [err, setErr] = useState('')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(false)
  const [doc, setDoc] = useState<{ title: string; html: string } | null>(null)
  const [docLoading, setDocLoading] = useState(false)

  // Prefill from external login challenge once it loads.
  if (challenge && !email && challenge.profileEmail) setEmail(challenge.profileEmail)
  if (challenge && !name && challenge.profileName) setName(challenge.profileName)

  const openDoc = async (which: 'tos' | 'privacy') => {
    const title = which === 'tos' ? '服务条款' : '隐私政策'
    setDoc({ title, html: '' })
    setDocLoading(true)
    try {
      const data = await api.get<{ content: string }>('/' + which)
      setDoc({ title, html: data.content || `<p style="color:#888">暂无${title}内容</p>` })
    } catch {
      setDoc({ title, html: `<p style="color:#dc2626">加载失败</p>` })
    } finally {
      setDocLoading(false)
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setFieldErrors({})
    setLoading(true)
    try {
      const { data } = await api.post<{ status: string; email: string }>('/register', {
        email,
        display_name: name,
        password: pw,
        confirm,
        agree_tos: agree,
        next,
        oidc_challenge: oidcChallenge,
      })
      const params = new URLSearchParams()
      if (data.email) params.set('email', data.email)
      params.set('status', data.status === 'init_failed' ? 'init_failed' : 'sent')
      navigate('/verify-email?' + params.toString())
    } catch (e2) {
      if (e2 instanceof ApiError) {
        setErr(e2.message)
        if (e2.fieldErrors) setFieldErrors(e2.fieldErrors)
      } else {
        setErr('注册失败')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthCard title="注册" footer={<Link to="/login">已有账号？登录</Link>}>
      {challenge && <div className="flash flash-ok">将注册并绑定到 {challenge.providerName} 账号。</div>}
      {err && <div className="flash flash-err">{err}</div>}
      <form onSubmit={submit}>
        <Input label="邮箱" type="email" value={email} onChange={(e) => setEmail(e.target.value)} error={fieldErrors.email} required autoFocus />
        <Input label="显示名称" value={name} onChange={(e) => setName(e.target.value)} error={fieldErrors.display_name} required />
        <Input label="密码" type="password" minLength={8} value={pw} onChange={(e) => setPw(e.target.value)} error={fieldErrors.password} required />
        <Input
          label="确认密码"
          type="password"
          minLength={8}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          error={fieldErrors.confirm}
          required
        />
        <div className="ti-consent">
          <input type="checkbox" id="agree" checked={agree} onChange={(e) => setAgree(e.target.checked)} />
          <label htmlFor="agree">
            我已阅读并同意
            <a onClick={() => openDoc('tos')}>《服务条款》</a>
            与
            <a onClick={() => openDoc('privacy')}>《隐私政策》</a>
          </label>
        </div>
        {fieldErrors.agree_tos && <div className="field-error">{fieldErrors.agree_tos}</div>}
        <Button type="submit" loading={loading} style={{ width: '100%', justifyContent: 'center', marginTop: '.4rem' }}>
          注册
        </Button>
      </form>
      <DocModal
        open={!!doc}
        title={doc?.title ?? ''}
        html={doc?.html ?? ''}
        loading={docLoading}
        onClose={() => setDoc(null)}
      />
    </AuthCard>
  )
}
