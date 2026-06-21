import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card, EmptyState, PageLoading, StatusText } from '@/components/ui'
import { Input, Select, FormGroup } from '@/components/form'
import { ProviderIcon } from '@/components/ProviderIcon'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'

// adminProviderDTO from internal/server/api_admin_misc.go (camelCase JSON).
// NOTE: the raw client secret is never returned; clientSecretSet reports whether
// one is configured so the SPA can render a "leave blank to keep" hint.
export interface AdminProvider {
  id: string
  name: string
  slug: string
  providerType: string
  icon: string
  clientId: string
  clientSecretSet: boolean
  issuerUrl: string
  authorizationUrl: string
  tokenUrl: string
  userinfoUrl: string
  scopes: string
  scopeList: string[]
  enabled: boolean
  autoRegister: boolean
  createdAt: string
}

// Quick-fill presets ported from web/static/js/provider_form.js.
interface ProviderPreset {
  name: string
  slug: string
  icon: string
  providerType: string
  issuerUrl: string
  authorizationUrl: string
  tokenUrl: string
  userinfoUrl: string
  scopes: string
}

const PRESETS: Record<string, ProviderPreset> = {
  google: {
    name: 'Google',
    slug: 'google',
    icon: 'google',
    providerType: 'oidc',
    issuerUrl: 'https://accounts.google.com',
    authorizationUrl: '',
    tokenUrl: '',
    userinfoUrl: '',
    scopes: 'openid email profile',
  },
  xcom: {
    name: 'X.com',
    slug: 'x',
    icon: 'x',
    providerType: 'oauth2',
    issuerUrl: '',
    authorizationUrl: 'https://x.com/i/oauth2/authorize',
    tokenUrl: 'https://api.x.com/2/oauth2/token',
    userinfoUrl: 'https://api.x.com/2/users/me?user.fields=id,name,username,profile_image_url',
    scopes: 'users.read tweet.read',
  },
}

const REQUIRED = <span style={{ color: '#dc2626' }}>*</span>

export default function Providers() {
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.providers,
    queryFn: () => api.get<AdminProvider[]>('/admin/providers'),
  })

  if (isLoading) return <PageLoading />

  const providers = data ?? []

  return (
    <>
      <h1 className="panel-title">登录方式</h1>
      <p className="panel-sub">配置外部身份提供商（OIDC / OAuth2），供用户登录时使用。</p>

      <CreateProviderCard />

      <Card style={{ padding: 0, marginTop: '1rem' }}>
        {isError ? (
          <EmptyState>加载登录方式失败，请稍后重试</EmptyState>
        ) : providers.length === 0 ? (
          <EmptyState>暂无登录方式，请使用上方表单添加</EmptyState>
        ) : (
          <ProvidersTable providers={providers} />
        )}
      </Card>
    </>
  )
}

// ── Create form ───────────────────────────────────────────────────────────────
const EMPTY_FORM = {
  name: '',
  slug: '',
  providerType: 'oidc',
  icon: '',
  clientId: '',
  clientSecret: '',
  issuerUrl: '',
  authorizationUrl: '',
  tokenUrl: '',
  userinfoUrl: '',
  scopes: '',
}

function CreateProviderCard() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [form, setForm] = useState({ ...EMPTY_FORM })
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  const set = (k: keyof typeof EMPTY_FORM, v: string) => setForm((f) => ({ ...f, [k]: v }))

  const isOIDC = form.providerType !== 'oauth2'

  function applyPreset(key: string) {
    const p = PRESETS[key]
    if (!p) return
    setForm({
      ...EMPTY_FORM,
      name: p.name,
      slug: p.slug,
      icon: p.icon,
      providerType: p.providerType,
      issuerUrl: p.issuerUrl,
      authorizationUrl: p.authorizationUrl,
      tokenUrl: p.tokenUrl,
      userinfoUrl: p.userinfoUrl,
      scopes: p.scopes,
    })
    setFieldErrors({})
  }

  const mutation = useMutation({
    // Field names mirror adminProviderCreateInput.
    mutationFn: () =>
      api.post<AdminProvider>('/admin/providers', {
        name: form.name.trim(),
        slug: form.slug.trim(),
        providerType: form.providerType,
        icon: form.icon.trim(),
        clientId: form.clientId.trim(),
        clientSecret: form.clientSecret,
        issuerUrl: form.issuerUrl.trim(),
        authorizationUrl: form.authorizationUrl.trim(),
        tokenUrl: form.tokenUrl.trim(),
        userinfoUrl: form.userinfoUrl.trim(),
        scopes: form.scopes.trim(),
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.providers })
      toast(res.flash || '登录方式已添加', 'success')
      setForm({ ...EMPTY_FORM })
      setFieldErrors({})
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        if (err.fieldErrors) setFieldErrors(err.fieldErrors)
        toast(err.message, 'error')
      } else {
        toast('创建失败', 'error')
      }
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (!form.name.trim()) errs.name = '名称不能为空'
    if (!form.slug.trim()) errs.slug = '路径标识不能为空'
    if (!form.clientId.trim()) errs.clientId = 'Client ID 不能为空'
    if (!form.clientSecret) errs.clientSecret = 'Client Secret 不能为空'
    if (isOIDC) {
      if (!form.issuerUrl.trim()) errs.issuerUrl = 'Issuer URL 不能为空'
    } else {
      if (!form.authorizationUrl.trim()) errs.authorizationUrl = 'Authorization URL 不能为空'
      if (!form.tokenUrl.trim()) errs.tokenUrl = 'Token URL 不能为空'
      if (!form.userinfoUrl.trim()) errs.userinfoUrl = 'Userinfo URL 不能为空'
    }
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    mutation.mutate()
  }

  return (
    <Card>
      <div className="detail-section-title">添加登录方式</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '.6rem', flexWrap: 'wrap', margin: '.4rem 0 1rem' }}>
        <span style={{ fontSize: '.82rem', color: 'var(--text2)' }}>快速填充：</span>
        <Button type="button" variant="ghost" size="sm" onClick={() => applyPreset('google')}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '.35rem' }}>
            <ProviderIcon slug="google" /> Google (OIDC)
          </span>
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => applyPreset('xcom')}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '.35rem' }}>
            <ProviderIcon slug="x" /> X.com (OAuth2)
          </span>
        </Button>
      </div>

      <form onSubmit={submit}>
        <div className="grid-2">
          <Input
            label={<>名称 {REQUIRED}</>}
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            error={fieldErrors.name}
            placeholder="Google"
          />
          <Input
            label={<>路径标识 (slug) {REQUIRED}</>}
            value={form.slug}
            onChange={(e) => set('slug', e.target.value)}
            error={fieldErrors.slug}
            hint="只能包含小写字母、数字和连字符"
            placeholder="google"
          />
        </div>

        <div className="grid-2">
          <Select
            label={<>协议类型 {REQUIRED}</>}
            value={form.providerType}
            onChange={(e) => set('providerType', e.target.value)}
          >
            <option value="oidc">OIDC</option>
            <option value="oauth2">OAuth2</option>
          </Select>
          <Input
            label="图标标识 (icon)"
            value={form.icon}
            onChange={(e) => set('icon', e.target.value)}
            hint="已知提供商（google / x）会自动显示内置图标"
            placeholder="google"
          />
        </div>

        <div className="grid-2">
          <Input
            label={<>Client ID {REQUIRED}</>}
            value={form.clientId}
            onChange={(e) => set('clientId', e.target.value)}
            error={fieldErrors.clientId}
          />
          <Input
            label={<>Client Secret {REQUIRED}</>}
            type="password"
            value={form.clientSecret}
            onChange={(e) => set('clientSecret', e.target.value)}
            error={fieldErrors.clientSecret}
            autoComplete="new-password"
          />
        </div>

        <ProtocolFields
          isOIDC={isOIDC}
          values={form}
          onChange={set}
          errors={fieldErrors}
        />

        <Input
          label="权限范围 (scopes，空格分隔)"
          value={form.scopes}
          onChange={(e) => set('scopes', e.target.value)}
          hint={
            isOIDC
              ? 'OIDC 建议权限范围：openid email profile（必须包含 openid）'
              : 'OAuth2 权限范围请按提供商文档填写（例如 users.read）'
          }
          placeholder={isOIDC ? 'openid email profile' : 'users.read'}
        />

        <div style={{ marginTop: '.6rem' }}>
          <Button type="submit" loading={mutation.isPending}>
            添加登录方式
          </Button>
        </div>
      </form>
    </Card>
  )
}

// Conditional protocol-specific endpoint fields, shared by create + edit forms.
export function ProtocolFields({
  isOIDC,
  values,
  onChange,
  errors,
}: {
  isOIDC: boolean
  values: { issuerUrl: string; authorizationUrl: string; tokenUrl: string; userinfoUrl: string }
  onChange: (k: 'issuerUrl' | 'authorizationUrl' | 'tokenUrl' | 'userinfoUrl', v: string) => void
  errors: Record<string, string>
}) {
  if (isOIDC) {
    return (
      <Input
        label={<>Issuer URL {REQUIRED}</>}
        value={values.issuerUrl}
        onChange={(e) => onChange('issuerUrl', e.target.value)}
        error={errors.issuerUrl}
        hint="OIDC 发行方地址，端点将通过 /.well-known 自动发现"
        placeholder="https://accounts.google.com"
      />
    )
  }
  return (
    <>
      <Input
        label={<>Authorization URL {REQUIRED}</>}
        value={values.authorizationUrl}
        onChange={(e) => onChange('authorizationUrl', e.target.value)}
        error={errors.authorizationUrl}
        placeholder="https://x.com/i/oauth2/authorize"
      />
      <Input
        label={<>Token URL {REQUIRED}</>}
        value={values.tokenUrl}
        onChange={(e) => onChange('tokenUrl', e.target.value)}
        error={errors.tokenUrl}
        placeholder="https://api.x.com/2/oauth2/token"
      />
      <Input
        label={<>Userinfo URL {REQUIRED}</>}
        value={values.userinfoUrl}
        onChange={(e) => onChange('userinfoUrl', e.target.value)}
        error={errors.userinfoUrl}
        placeholder="https://api.x.com/2/users/me"
      />
    </>
  )
}

// ── Providers table ───────────────────────────────────────────────────────────
function ProvidersTable({ providers }: { providers: AdminProvider[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  function onError(err: unknown) {
    if (err instanceof ApiError) toast(err.message, 'error')
    else toast('操作失败', 'error')
  }

  const toggle = useMutation({
    mutationFn: (id: string) => api.post('/admin/providers/' + id + '/toggle'),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.providers })
      toast(res.flash || '已更新', 'success')
    },
    onError,
  })

  const del = useMutation({
    mutationFn: (id: string) => api.del('/admin/providers/' + id),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.providers })
      toast(res.flash || '已删除', 'success')
    },
    onError,
  })

  async function onDelete(p: AdminProvider) {
    const ok = await confirm({
      title: '删除登录方式',
      message: `确定要删除「${p.name}」吗？此操作不可撤销。`,
      confirmLabel: '删除',
      danger: true,
    })
    if (ok) del.mutate(p.id)
  }

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>名称</th>
            <th>标识</th>
            <th>协议</th>
            <th>权限范围</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {providers.map((p) => (
            <tr key={p.id}>
              <td>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '.45rem', fontWeight: 500 }}>
                  <ProviderIcon slug={p.slug} icon={p.icon} />
                  {p.name}
                </span>
              </td>
              <td>
                <code className="mono" style={{ color: 'var(--blue-d)' }}>
                  {p.slug}
                </code>
              </td>
              <td style={{ textTransform: 'uppercase', fontSize: '.78rem' }}>{p.providerType}</td>
              <td style={{ fontSize: '.8rem' }}>
                {p.scopeList?.map((s) => (
                  <span key={s} className="proj-tag">
                    {s}
                  </span>
                ))}
              </td>
              <td>
                <StatusText active={p.enabled} />
              </td>
              <td>
                <div style={{ display: 'flex', gap: '.4rem', flexWrap: 'wrap' }}>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => toggle.mutate(p.id)}
                    loading={toggle.isPending && toggle.variables === p.id}
                  >
                    {p.enabled ? '停用' : '启用'}
                  </Button>
                  <Link to={`/admin/providers/${p.id}/edit`} className="btn btn-ghost btn-sm">
                    编辑
                  </Link>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => onDelete(p)}
                    loading={del.isPending && del.variables === p.id}
                  >
                    删除
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
