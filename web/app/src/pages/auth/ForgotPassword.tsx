import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button } from '@/components/ui'
import { Input } from '@/components/form'

export default function ForgotPassword() {
  const [sp] = useSearchParams()
  const next = sp.get('next') ?? ''
  const [email, setEmail] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setMsg('')
    setLoading(true)
    try {
      const { flash } = await api.post('/forgot-password', { email, next })
      setMsg(flash ?? '如果该邮箱已注册，系统已发送重置密码邮件。')
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : '发送失败，请稍后重试。')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthCard title="忘记密码" footer={<Link to="/login">返回登录</Link>}>
      {msg && <div className="flash flash-ok">{msg}</div>}
      {err && <div className="flash flash-err">{err}</div>}
      <form onSubmit={submit}>
        <Input label="邮箱" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        <Button type="submit" loading={loading} style={{ width: '100%', justifyContent: 'center' }}>
          发送重置邮件
        </Button>
      </form>
    </AuthCard>
  )
}
