import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card, EmptyState, PageLoading } from '@/components/ui'
import { Input, Select } from '@/components/form'
import { ProviderIcon } from '@/components/ProviderIcon'
import { useToast } from '@/providers/ToastProvider'
import { ProtocolFields, type AdminProvider } from './Providers'

const REQUIRED = <span style={{ color: '#dc2626' }}>*</span>

export default function ProviderEdit() {
  const { id = '' } = useParams()
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.provider(id),
    queryFn: () => api.get<AdminProvider>('/admin/providers/' + id),
    enabled: !!id,
  })

  if (isLoading) return <PageLoading />
  if (isError || !data) {
    return (
      <>
        <h1 className="panel-title">编辑登录方式</h1>
        <Card>
          <EmptyState>提供商不存在或加载失败</EmptyState>
          <div style={{ textAlign: 'center' }}>
            <Link to="/admin/providers" className="btn btn-ghost btn-sm">
              返回列表
            </Link>
          </div>
        </Card>
      </>
    )
  }

  return <EditForm id={id} provider={data} />
}

function EditForm({ id, provider }: { id: string; provider: AdminProvider }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const { toast } = useToast()

  const [name, setName] = useState(provider.name)
  const [providerType, setProviderType] = useState(provider.providerType || 'oidc')
  const [icon, setIcon] = useState(provider.icon)
  const [clientId, setClientId] = useState(provider.clientId)
  const [clientSecret, setClientSecret] = useState('')
  const [issuerUrl, setIssuerUrl] = useState(provider.issuerUrl)
  const [authorizationUrl, setAuthorizationUrl] = useState(provider.authorizationUrl)
  const [tokenUrl, setTokenUrl] = useState(provider.tokenUrl)
  const [userinfoUrl, setUserinfoUrl] = useState(provider.userinfoUrl)
  const [scopes, setScopes] = useState(provider.scopes)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  // Re-sync when the provider refetches after a save.
  useEffect(() => {
    setName(provider.name)
    setProviderType(provider.providerType || 'oidc')
    setIcon(provider.icon)
    setClientId(provider.clientId)
    setIssuerUrl(provider.issuerUrl)
    setAuthorizationUrl(provider.authorizationUrl)
    setTokenUrl(provider.tokenUrl)
    setUserinfoUrl(provider.userinfoUrl)
    setScopes(provider.scopes)
  }, [provider])

  const isOIDC = providerType !== 'oauth2'

  const protocolValues = { issuerUrl, authorizationUrl, tokenUrl, userinfoUrl }
  const setProtocol = (k: 'issuerUrl' | 'authorizationUrl' | 'tokenUrl' | 'userinfoUrl', v: string) => {
    if (k === 'issuerUrl') setIssuerUrl(v)
    else if (k === 'authorizationUrl') setAuthorizationUrl(v)
    else if (k === 'tokenUrl') setTokenUrl(v)
    else setUserinfoUrl(v)
  }

  const mutation = useMutation({
    // Field names mirror adminProviderEditInput. clientSecret left blank keeps
    // the existing value; clientId blank keeps existing too (handler behaviour).
    mutationFn: () =>
      api.patch<AdminProvider>('/admin/providers/' + id, {
        name: name.trim(),
        providerType,
        icon: icon.trim(),
        clientId: clientId.trim(),
        clientSecret,
        issuerUrl: issuerUrl.trim(),
        authorizationUrl: authorizationUrl.trim(),
        tokenUrl: tokenUrl.trim(),
        userinfoUrl: userinfoUrl.trim(),
        scopes: scopes.trim(),
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.providers })
      qc.invalidateQueries({ queryKey: qk.provider(id) })
      toast(res.flash || '已更新', 'success')
      navigate('/admin/providers')
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        if (err.fieldErrors) setFieldErrors(err.fieldErrors)
        toast(err.message, 'error')
      } else {
        toast('更新失败', 'error')
      }
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (!name.trim()) errs.name = '名称不能为空'
    if (isOIDC) {
      if (!issuerUrl.trim()) errs.issuerUrl = 'Issuer URL 不能为空'
    } else {
      if (!authorizationUrl.trim()) errs.authorizationUrl = 'Authorization URL 不能为空'
      if (!tokenUrl.trim()) errs.tokenUrl = 'Token URL 不能为空'
      if (!userinfoUrl.trim()) errs.userinfoUrl = 'Userinfo URL 不能为空'
    }
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    mutation.mutate()
  }

  return (
    <>
      <p className="panel-sub" style={{ marginBottom: '.5rem' }}>
        <Link to="/admin/providers">← 返回列表</Link>
      </p>
      <h1 className="panel-title">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '.45rem' }}>
          <ProviderIcon slug={provider.slug} icon={provider.icon} />
          编辑「{provider.name}」
        </span>
      </h1>
      <p className="panel-sub">
        路径标识：<code className="mono">{provider.slug}</code>（不可修改）
      </p>

      <Card>
        <form onSubmit={submit}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <Input
              label={<>名称 {REQUIRED}</>}
              value={name}
              onChange={(e) => setName(e.target.value)}
              error={fieldErrors.name}
            />
            <Select
              label={<>协议类型 {REQUIRED}</>}
              value={providerType}
              onChange={(e) => setProviderType(e.target.value)}
            >
              <option value="oidc">OIDC</option>
              <option value="oauth2">OAuth2</option>
            </Select>
          </div>

          <Input
            label="图标标识 (icon)"
            value={icon}
            onChange={(e) => setIcon(e.target.value)}
            hint="已知提供商（google / x）会自动显示内置图标"
          />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <Input
              label="Client ID"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              hint="留空保持原值不变"
            />
            <Input
              label="Client Secret"
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              autoComplete="new-password"
              placeholder={provider.clientSecretSet ? '已配置，留空保持不变' : '尚未配置'}
              hint="留空保持原值不变"
            />
          </div>

          <ProtocolFields isOIDC={isOIDC} values={protocolValues} onChange={setProtocol} errors={fieldErrors} />

          <Input
            label="权限范围 (scopes，空格分隔)"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            hint={
              isOIDC
                ? 'OIDC 建议权限范围：openid email profile（必须包含 openid）'
                : 'OAuth2 权限范围请按提供商文档填写（例如 users.read）'
            }
            placeholder={isOIDC ? 'openid email profile' : 'users.read'}
          />

          <div style={{ display: 'flex', gap: '.8rem', marginTop: '.6rem' }}>
            <Button type="submit" loading={mutation.isPending}>
              保存修改
            </Button>
            <Link to="/admin/providers" className="btn btn-ghost">
              取消
            </Link>
          </div>
        </form>
      </Card>
    </>
  )
}
