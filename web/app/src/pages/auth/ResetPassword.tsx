import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button } from '@/components/ui'
import { Input } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'

export default function ResetPassword() {
  const [sp] = useSearchParams()
  const token = sp.get('token') ?? ''
  const navigate = useNavigate()
  const { toast } = useToast()
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setLoading(true)
    try {
      const { flash } = await api.post('/reset-password', { token, new_password: pw, confirm_password: confirm })
      toast(flash ?? '密码已重置，请使用新密码登录。', 'success')
      navigate('/login')
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : '重置失败，请稍后重试。')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthCard title="重置密码" footer={<Link to="/login">返回登录</Link>}>
      {!token && <div className="flash flash-err">重置链接无效，请重新申请找回密码。</div>}
      {err && <div className="flash flash-err">{err}</div>}
      <form onSubmit={submit}>
        <Input label="新密码" type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required autoFocus />
        <Input label="确认新密码" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} minLength={8} required />
        <Button type="submit" loading={loading} disabled={!token} style={{ width: '100%', justifyContent: 'center' }}>
          重置密码
        </Button>
      </form>
    </AuthCard>
  )
}
