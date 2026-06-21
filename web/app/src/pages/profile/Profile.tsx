import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card, RoleBadge, PageLoading, StatusText } from '@/components/ui'
import { Input, FormGroup } from '@/components/form'
import { Modal } from '@/components/Modal'
import { ProviderIcon } from '@/components/ProviderIcon'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'
import { useAuth } from '@/providers/AuthProvider'
import { registerPasskey } from '@/lib/webauthn'
import type { User } from '@/api/types'

interface Passkey {
  id: string
  name: string
  createdAt: string
}
interface ExternalProvider {
  slug: string
  name: string
  icon: string
  enabled: boolean
  bound: boolean
}
interface ProfileView {
  user: User
  hasPassword: boolean
  passkeys: Passkey[]
  passkeyCount: number
  externalProviders: ExternalProvider[]
  totpEnabled: boolean
  pendingSecret?: string
  pendingUri?: string
}

export default function Profile() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()
  const { refresh } = useAuth()
  const { data, isLoading } = useQuery({ queryKey: qk.profile, queryFn: () => api.get<ProfileView>('/profile') })

  const invalidate = async () => {
    await qc.invalidateQueries({ queryKey: qk.profile })
    await refresh()
  }

  if (isLoading || !data) return <PageLoading />

  return (
    <>
      <h1 className="panel-title">个人资料</h1>
      <p className="panel-sub">管理您的账号信息、安全设置与登录方式。</p>

      <AccountOverview view={data} />
      <ExternalIdentities view={data} onChange={invalidate} />
      <BasicInfo view={data} onSaved={invalidate} />
      <PasswordSection view={data} onSaved={invalidate} />
      <TwoFactorSection view={data} onChange={invalidate} />
      <PasskeySection view={data} onChange={invalidate} confirm={confirm} toast={toast} />
    </>
  )
}

function flashOf(e: unknown) {
  return e instanceof ApiError ? e.message : '操作失败'
}

function AccountOverview({ view }: { view: ProfileView }) {
  const u = view.user
  return (
    <Card style={{ marginTop: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>账号概览</h3>
      <div className="auto-grid">
        <div>
          <div className="form-label">邮箱</div>
          <div>
            {u.email} {u.emailVerified ? <StatusText active on="已验证" /> : <StatusText active={false} off="未验证" />}
          </div>
        </div>
        <div>
          <div className="form-label">角色</div>
          <div>
            <RoleBadge role={u.role} />
          </div>
        </div>
        <div>
          <div className="form-label">双重验证</div>
          <div>{view.totpEnabled ? <StatusText active on="已启用" /> : <StatusText active={false} off="未启用" />}</div>
        </div>
      </div>
    </Card>
  )
}

function ExternalIdentities({ view, onChange }: { view: ProfileView; onChange: () => void }) {
  const { toast } = useToast()
  const [busy, setBusy] = useState('')
  if (!view.externalProviders || view.externalProviders.length === 0) return null

  const bind = async (slug: string) => {
    setBusy(slug)
    try {
      const { data } = await api.post<{ location: string }>(`/profile/identities/${slug}/bind`)
      window.location.assign(data.location)
    } catch (e) {
      toast(flashOf(e), 'error')
      setBusy('')
    }
  }
  const unbind = async (slug: string) => {
    setBusy(slug)
    try {
      const { flash } = await api.post(`/profile/identities/${slug}/unbind`)
      toast(flash ?? '已解绑', 'success')
      onChange()
    } catch (e) {
      toast(flashOf(e), 'error')
    } finally {
      setBusy('')
    }
  }

  return (
    <Card style={{ marginTop: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>外部登录方式</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '.6rem' }}>
        {view.externalProviders.map((p) => (
          <div key={p.slug} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '.6rem' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '.5rem' }}>
              <ProviderIcon slug={p.slug} icon={p.icon} />
              {p.name}
              {p.bound && <StatusText active on="已绑定" />}
            </span>
            {p.bound ? (
              <Button variant="ghost" size="sm" disabled={busy === p.slug} onClick={() => unbind(p.slug)}>
                解绑
              </Button>
            ) : (
              <Button variant="ghost" size="sm" disabled={!p.enabled || busy === p.slug} onClick={() => bind(p.slug)}>
                绑定
              </Button>
            )}
          </div>
        ))}
      </div>
    </Card>
  )
}

function BasicInfo({ view, onSaved }: { view: ProfileView; onSaved: () => void }) {
  const { toast } = useToast()
  const [name, setName] = useState(view.user.displayName)
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState(view.user.avatarUrl)
  const [clear, setClear] = useState(false)
  const [saving, setSaving] = useState(false)

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] ?? null
    setFile(f)
    if (f) {
      setPreview(URL.createObjectURL(f))
      setClear(false)
    }
  }

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const fd = new FormData()
      fd.set('display_name', name)
      if (clear) fd.set('clear_avatar', '1')
      if (file) fd.set('avatar_file', file)
      const { flash } = await api.postForm('/profile', fd)
      toast(flash ?? '已保存', 'success')
      setFile(null)
      onSaved()
    } catch (err) {
      toast(flashOf(err), 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card style={{ marginTop: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>基本信息</h3>
      <form onSubmit={save}>
        <Input label="显示名称" value={name} onChange={(e) => setName(e.target.value)} required />
        <FormGroup label="头像">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {preview && !clear ? (
              <img src={preview} alt="头像" style={{ width: 56, height: 56, borderRadius: '50%', objectFit: 'cover' }} />
            ) : (
              <div style={{ width: 56, height: 56, borderRadius: '50%', background: '#f1f5f9' }} />
            )}
            <input type="file" accept="image/*" onChange={onFile} />
          </div>
        </FormGroup>
        {view.user.avatarUrl && (
          <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', fontSize: '.85rem', marginBottom: '.8rem' }}>
            <input type="checkbox" checked={clear} onChange={(e) => setClear(e.target.checked)} />
            清除当前头像
          </label>
        )}
        <Button type="submit" loading={saving}>
          保存
        </Button>
      </form>
    </Card>
  )
}

function PasswordSection({ view, onSaved }: { view: ProfileView; onSaved: () => void }) {
  const { toast } = useToast()
  const confirm = useConfirm()
  const [cur, setCur] = useState('')
  const [pw, setPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [saving, setSaving] = useState(false)

  const change = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const fd = new FormData()
      fd.set('display_name', view.user.displayName)
      fd.set('current_password', cur)
      fd.set('new_password', pw)
      fd.set('confirm_password', confirmPw)
      const { flash } = await api.postForm('/profile', fd)
      toast(flash ?? '密码已更新', 'success')
      setCur('')
      setPw('')
      setConfirmPw('')
      onSaved()
    } catch (err) {
      toast(flashOf(err), 'error')
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    if (!(await confirm({ message: '删除密码后将只能使用通行密钥登录，确定继续吗？', danger: true }))) return
    try {
      const { flash } = await api.post('/profile/delete-password')
      toast(flash ?? '密码已删除', 'success')
      onSaved()
    } catch (err) {
      toast(flashOf(err), 'error')
    }
  }

  return (
    <Card style={{ marginTop: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>密码</h3>
      {view.hasPassword ? (
        <form onSubmit={change}>
          <Input label="当前密码" type="password" value={cur} onChange={(e) => setCur(e.target.value)} required />
          <Input label="新密码" type="password" minLength={8} value={pw} onChange={(e) => setPw(e.target.value)} required />
          <Input label="确认新密码" type="password" minLength={8} value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} required />
          <div style={{ display: 'flex', gap: '.6rem' }}>
            <Button type="submit" loading={saving}>
              更新密码
            </Button>
            {view.passkeyCount > 0 && (
              <Button type="button" variant="ghost" onClick={remove}>
                删除密码（仅用通行密钥）
              </Button>
            )}
          </div>
        </form>
      ) : (
        <p style={{ color: 'var(--text2)' }}>当前账号未设置密码，使用通行密钥登录。</p>
      )}
    </Card>
  )
}

function TwoFactorSection({ view, onChange }: { view: ProfileView; onChange: () => void }) {
  const { toast } = useToast()
  const [code, setCode] = useState('')
  const [cur, setCur] = useState('')
  const [busy, setBusy] = useState(false)

  const start = async () => {
    setBusy(true)
    try {
      const { flash } = await api.post('/profile/2fa/start')
      toast(flash ?? '已生成密钥', 'success')
      onChange()
    } catch (e) {
      toast(flashOf(e), 'error')
    } finally {
      setBusy(false)
    }
  }
  const enable = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const { flash } = await api.post('/profile/2fa/enable', { totp_code: code })
      toast(flash ?? '双重验证已启用', 'success')
      setCode('')
      onChange()
    } catch (err) {
      toast(flashOf(err), 'error')
    } finally {
      setBusy(false)
    }
  }
  const disable = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const { flash } = await api.post('/profile/2fa/disable', { current_password: cur, totp_code: code })
      toast(flash ?? '双重验证已关闭', 'success')
      setCur('')
      setCode('')
      onChange()
    } catch (err) {
      toast(flashOf(err), 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card style={{ marginTop: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>双重验证（动态口令）</h3>
      {view.totpEnabled ? (
        <form onSubmit={disable}>
          <p style={{ color: 'var(--text2)' }}>双重验证已启用。关闭请提供当前密码或动态口令验证码。</p>
          {view.hasPassword && <Input label="当前密码" type="password" value={cur} onChange={(e) => setCur(e.target.value)} />}
          <Input label="动态口令验证码" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} />
          <Button type="submit" variant="danger" loading={busy}>
            关闭双重验证
          </Button>
        </form>
      ) : view.pendingSecret ? (
        <form onSubmit={enable}>
          <p style={{ color: 'var(--text2)' }}>使用验证器 App 扫描二维码，或手动输入密钥，然后输入 6 位验证码完成启用。</p>
          <div style={{ display: 'flex', gap: '1.2rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '.8rem' }}>
            <img src="/profile/2fa/qr" alt="TOTP 二维码" style={{ width: 'min(180px, 55vw)', height: 'auto', border: '1px solid #eee', borderRadius: 8 }} />
            <code style={{ wordBreak: 'break-all', background: '#f8fafc', padding: '.4rem .6rem', borderRadius: 6 }}>{view.pendingSecret}</code>
          </div>
          <Input label="动态口令验证码" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required />
          <Button type="submit" loading={busy}>
            启用双重验证
          </Button>
        </form>
      ) : (
        <>
          <p style={{ color: 'var(--text2)' }}>启用动态口令后，登录时需要额外输入验证器 App 生成的验证码。</p>
          <Button onClick={start} loading={busy}>
            开始设置
          </Button>
        </>
      )}
    </Card>
  )
}

function PasskeySection({
  view,
  onChange,
  confirm,
  toast,
}: {
  view: ProfileView
  onChange: () => void
  confirm: ReturnType<typeof useConfirm>
  toast: ReturnType<typeof useToast>['toast']
}) {
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Passkey | null>(null)
  const [delPw, setDelPw] = useState('')
  const [delCode, setDelCode] = useState('')

  const register = async () => {
    setBusy(true)
    try {
      await registerPasskey(name || '通行密钥')
      toast('通行密钥注册成功', 'success')
      setName('')
      onChange()
    } catch (e) {
      toast(e instanceof Error ? e.message : '注册失败', 'error')
    } finally {
      setBusy(false)
    }
  }

  const doDelete = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!deleteTarget) return
    try {
      const { flash } = await api.post(`/profile/passkey/${deleteTarget.id}/delete`, {
        current_password: delPw,
        totp_code: delCode,
      })
      toast(flash ?? '通行密钥已删除', 'success')
      setDeleteTarget(null)
      setDelPw('')
      setDelCode('')
      onChange()
    } catch (err) {
      toast(flashOf(err), 'error')
    }
  }

  void confirm
  return (
    <Card style={{ marginTop: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>通行密钥（Passkey）</h3>
      {view.passkeys.length === 0 ? (
        <p style={{ color: 'var(--text2)' }}>尚未注册任何通行密钥。</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table" style={{ marginBottom: '1rem' }}>
            <thead>
              <tr>
                <th>名称</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {view.passkeys.map((p) => (
                <tr key={p.id}>
                  <td>{p.name}</td>
                  <td>{new Date(p.createdAt).toLocaleString()}</td>
                  <td>
                    <Button variant="ghost" size="sm" onClick={() => setDeleteTarget(p)}>
                      删除
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div style={{ display: 'flex', gap: '.6rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <Input label="新通行密钥名称" value={name} onChange={(e) => setName(e.target.value)} placeholder="例如：我的手机" />
        <Button onClick={register} loading={busy}>
          注册通行密钥
        </Button>
      </div>

      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="删除通行密钥">
        <p style={{ color: 'var(--text2)' }}>请提供当前密码或动态口令验证码以确认删除「{deleteTarget?.name}」。</p>
        <form onSubmit={doDelete}>
          {view.hasPassword && <Input label="当前密码" type="password" value={delPw} onChange={(e) => setDelPw(e.target.value)} />}
          {view.totpEnabled && <Input label="动态口令验证码" inputMode="numeric" value={delCode} onChange={(e) => setDelCode(e.target.value)} />}
          <div style={{ display: 'flex', gap: '.6rem', justifyContent: 'flex-end' }}>
            <Button type="button" variant="ghost" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button type="submit" variant="danger">
              确认删除
            </Button>
          </div>
        </form>
      </Modal>
    </Card>
  )
}
