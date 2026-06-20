import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, PageLoading, EmptyState } from '@/components/ui'
import { Input, Select, Textarea, FormGroup } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'

// The settings GET returns a flat map. Plain keys hold their value directly;
// secret keys are never echoed — only "<key>Set" booleans report whether one is
// configured (smtp_passSet / resend_api_keySet).
interface SettingsResponse {
  site_name?: string
  contact_email?: string
  site_icon_url?: string
  ann_zh?: string
  ann_en?: string
  tos_content?: string
  privacy_content?: string
  email_provider?: string
  smtp_host?: string
  smtp_port?: string
  smtp_user?: string
  smtp_from?: string
  resend_from?: string
  email_tpl_welcome?: string
  email_tpl_password_reset?: string
  smtp_passSet?: boolean
  resend_api_keySet?: boolean
  [key: string]: string | boolean | undefined
}

// The editable plain (non-secret) string fields, keyed by their exact API key.
const PLAIN_KEYS = [
  'site_name',
  'contact_email',
  'site_icon_url',
  'ann_zh',
  'ann_en',
  'tos_content',
  'privacy_content',
  'email_provider',
  'smtp_host',
  'smtp_port',
  'smtp_user',
  'smtp_from',
  'resend_from',
  'email_tpl_welcome',
  'email_tpl_password_reset',
] as const

type PlainKey = (typeof PLAIN_KEYS)[number]
type FormState = Record<PlainKey, string>

function initialForm(data: SettingsResponse | undefined): FormState {
  const out = {} as FormState
  for (const k of PLAIN_KEYS) {
    const v = data?.[k]
    out[k] = typeof v === 'string' ? v : ''
  }
  return out
}

export default function Settings() {
  const qc = useQueryClient()
  const { toast } = useToast()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.settings,
    queryFn: () => api.get<SettingsResponse>('/admin/settings'),
  })

  const [form, setForm] = useState<FormState>(() => initialForm(undefined))
  // Secret fields are write-only: blank means "leave unchanged".
  const [smtpPass, setSmtpPass] = useState('')
  const [resendKey, setResendKey] = useState('')

  // Hydrate the local form once the settings load / change.
  useEffect(() => {
    if (data) {
      setForm(initialForm(data))
      setSmtpPass('')
      setResendKey('')
    }
  }, [data])

  const set = (key: PlainKey, value: string) => setForm((f) => ({ ...f, [key]: value }))

  const save = useMutation({
    mutationFn: () => {
      // Only send fields that changed from the loaded value; secrets only when typed.
      const body: Record<string, string> = {}
      for (const k of PLAIN_KEYS) {
        const original = typeof data?.[k] === 'string' ? (data[k] as string) : ''
        if (form[k] !== original) body[k] = form[k]
      }
      if (smtpPass) body.smtp_pass = smtpPass
      if (resendKey) body.resend_api_key = resendKey
      return api.patch('/admin/settings', body)
    },
    onSuccess: (res) => {
      toast(res.flash || '设置已保存', 'success')
      setSmtpPass('')
      setResendKey('')
      qc.invalidateQueries({ queryKey: qk.settings })
    },
    onError: (err) => {
      toast(err instanceof ApiError ? err.message : '保存失败', 'error')
    },
  })

  if (isLoading && !data) return <PageLoading />
  if (isError || !data) {
    return (
      <>
        <h1 className="panel-title">站点设置</h1>
        <div className="card">
          <EmptyState>加载站点设置失败，请稍后重试</EmptyState>
        </div>
      </>
    )
  }

  const provider = form.email_provider || 'smtp'

  return (
    <>
      <h1 className="panel-title">站点设置</h1>
      <p className="panel-sub">配置站点信息、法律文档、公告与邮件发送服务。</p>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          save.mutate()
        }}
        style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
      >
        {/* ── 基本信息 ─────────────────────────────────────────────────────── */}
        <div className="card">
          <h2 className="form-panel-title">基本信息</h2>
          <Input
            label="站点名称"
            value={form.site_name}
            onChange={(e) => set('site_name', e.target.value)}
          />
          <Input
            label="联系邮箱"
            type="email"
            value={form.contact_email}
            onChange={(e) => set('contact_email', e.target.value)}
          />
          <IconUpload currentUrl={form.site_icon_url} />
          <Input
            label="站点图标 URL"
            value={form.site_icon_url}
            onChange={(e) => set('site_icon_url', e.target.value)}
            hint="可直接填写图标地址，或使用上方上传。"
          />
        </div>

        {/* ── 法律文档 ─────────────────────────────────────────────────────── */}
        <div className="card">
          <h2 className="form-panel-title">法律文档</h2>
          <Textarea
            label="服务条款（ToS）"
            rows={6}
            value={form.tos_content}
            onChange={(e) => set('tos_content', e.target.value)}
          />
          <Textarea
            label="隐私政策"
            rows={6}
            value={form.privacy_content}
            onChange={(e) => set('privacy_content', e.target.value)}
          />
        </div>

        {/* ── 全站公告 ─────────────────────────────────────────────────────── */}
        <div className="card">
          <h2 className="form-panel-title">全站公告</h2>
          <Textarea
            label="公告（中文）"
            rows={3}
            value={form.ann_zh}
            onChange={(e) => set('ann_zh', e.target.value)}
          />
          <Textarea
            label="公告（English）"
            rows={3}
            value={form.ann_en}
            onChange={(e) => set('ann_en', e.target.value)}
          />
        </div>

        {/* ── 邮件服务 ─────────────────────────────────────────────────────── */}
        <div className="card">
          <h2 className="form-panel-title">邮件服务</h2>
          <Select
            label="邮件服务商"
            value={provider}
            onChange={(e) => set('email_provider', e.target.value)}
          >
            <option value="smtp">SMTP</option>
            <option value="resend">Resend</option>
          </Select>

          {provider === 'resend' ? (
            <>
              <SecretInput
                label="Resend API Key"
                isSet={!!data.resend_api_keySet}
                value={resendKey}
                onChange={setResendKey}
              />
              <Input
                label="发件地址（Resend From）"
                value={form.resend_from}
                onChange={(e) => set('resend_from', e.target.value)}
              />
            </>
          ) : (
            <>
              <Input
                label="SMTP 主机"
                value={form.smtp_host}
                onChange={(e) => set('smtp_host', e.target.value)}
              />
              <Input
                label="SMTP 端口"
                value={form.smtp_port}
                onChange={(e) => set('smtp_port', e.target.value)}
              />
              <Input
                label="SMTP 用户名"
                value={form.smtp_user}
                onChange={(e) => set('smtp_user', e.target.value)}
              />
              <SecretInput
                label="SMTP 密码"
                isSet={!!data.smtp_passSet}
                value={smtpPass}
                onChange={setSmtpPass}
              />
              <Input
                label="发件地址（SMTP From）"
                value={form.smtp_from}
                onChange={(e) => set('smtp_from', e.target.value)}
              />
            </>
          )}
        </div>

        {/* ── 邮件模板 ─────────────────────────────────────────────────────── */}
        <div className="card">
          <h2 className="form-panel-title">邮件模板</h2>
          <Textarea
            label="欢迎邮件模板"
            rows={5}
            value={form.email_tpl_welcome}
            onChange={(e) => set('email_tpl_welcome', e.target.value)}
          />
          <Textarea
            label="重置密码邮件模板"
            rows={5}
            value={form.email_tpl_password_reset}
            onChange={(e) => set('email_tpl_password_reset', e.target.value)}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button type="submit" loading={save.isPending}>
            保存设置
          </Button>
        </div>
      </form>
    </>
  )
}

// SecretInput renders a write-only credential field. It never shows the stored
// value; instead it hints whether one is already configured and only emits a
// value when the admin types a new one.
function SecretInput({
  label,
  isSet,
  value,
  onChange,
}: {
  label: string
  isSet: boolean
  value: string
  onChange: (v: string) => void
}) {
  return (
    <Input
      label={label}
      type="password"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      autoComplete="new-password"
      placeholder={isSet ? '已配置 — 留空保持不变' : '未配置'}
      hint={isSet ? '已配置，留空表示不修改。' : '尚未配置。'}
    />
  )
}

// IconUpload handles the multipart icon upload (field name: icon_file) with a
// live preview, independent of the main settings save.
function IconUpload({ currentUrl }: { currentUrl: string }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const inputRef = useRef<HTMLInputElement>(null)
  const [preview, setPreview] = useState<string | null>(null)

  const upload = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData()
      fd.append('icon_file', file)
      return api.postForm<{ iconUrl: string }>('/admin/settings/icon', fd)
    },
    onSuccess: (res) => {
      toast(res.flash || '图标已上传', 'success')
      qc.invalidateQueries({ queryKey: qk.settings })
      if (inputRef.current) inputRef.current.value = ''
    },
    onError: (err) => {
      toast(err instanceof ApiError ? err.message : '上传失败', 'error')
    },
  })

  function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setPreview(URL.createObjectURL(file))
    upload.mutate(file)
  }

  const shown = preview || currentUrl

  return (
    <FormGroup label="站点图标" hint="支持 PNG/JPG/SVG，最大 5MB。">
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        {shown ? (
          <img
            src={shown}
            alt="站点图标预览"
            style={{
              width: 56,
              height: 56,
              objectFit: 'contain',
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--bg2, #fff)',
            }}
          />
        ) : (
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: 8,
              border: '1px dashed var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text2)',
              fontSize: '.75rem',
            }}
          >
            无
          </div>
        )}
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          onChange={onPick}
          disabled={upload.isPending}
        />
        {upload.isPending && <span style={{ color: 'var(--text2)', fontSize: '.85rem' }}>上传中…</span>}
      </div>
    </FormGroup>
  )
}
