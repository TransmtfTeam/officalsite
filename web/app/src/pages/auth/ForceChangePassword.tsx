import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button } from '@/components/ui'
import { Input } from '@/components/form'
import { useAuth } from '@/providers/AuthProvider'
import { safeNext } from '@/lib/nav'

export default function ForceChangePassword() {
  const [sp] = useSearchParams()
  const next = sp.get('next') ?? ''
  const navigate = useNavigate()
  const { refresh } = useAuth()
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    setLoading(true)
    try {
      const { data } = await api.post<{ redirect?: string }>('/profile/change-password', {
        new_password: pw,
        confirm_password: confirm,
        next,
      })
      await refresh()
      navigate(safeNext(data.redirect, '/profile'))
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : '密码更新失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthCard title="修改密码">
      <p style={{ color: 'var(--text2)', fontSize: '.9rem', marginTop: 0 }}>为了账户安全，请在继续之前设置新的密码。</p>
      {err && <div className="flash flash-err">{err}</div>}
      <form onSubmit={submit}>
        <Input label="新密码" type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required autoFocus />
        <Input label="确认新密码" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} minLength={8} required />
        <Button type="submit" loading={loading} style={{ width: '100%', justifyContent: 'center' }}>
          保存并继续
        </Button>
      </form>
    </AuthCard>
  )
}
