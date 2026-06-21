import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card, EmptyState, PageLoading } from '@/components/ui'
import { Input, Select, Textarea, FormGroup } from '@/components/form'
import { Modal } from '@/components/Modal'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'
import { useAuth } from '@/providers/AuthProvider'
import type { AdminClient } from './Clients'

// integration endpoints from adminClientIntegrationDTO.
interface ClientIntegration {
  issuer: string
  discoveryEndpoint: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  jwksEndpoint: string
}

// adminGroupDTO from internal/server/api_admin_users.go.
interface GroupDTO {
  id: string
  name: string
  label: string
  createdAt: string
}

// Shape of GET /admin/clients/{id}.
interface ClientDetailResponse {
  client: AdminClient
  integration: ClientIntegration
  groups: GroupDTO[]
  managerGroups: string[]
}

const BASE_ACCESS_LABELS: Record<string, string> = {
  legacy: '兼容模式',
  user: '所有已登录用户',
  member: '成员及以上',
  admin: '仅管理员',
  none: '仅按分组（无基础权限）',
}

function fmt(ts: string): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}

export default function ClientDetail() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()
  const navigate = useNavigate()
  const { isAdmin } = useAuth()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.client(id),
    queryFn: () => api.get<ClientDetailResponse>('/admin/clients/' + id),
    enabled: !!id,
  })

  function afterMutation(flash?: string) {
    qc.invalidateQueries({ queryKey: qk.client(id) })
    qc.invalidateQueries({ queryKey: qk.clients })
    if (flash) toast(flash, 'success')
  }
  function onMutationError(err: unknown) {
    if (err instanceof ApiError) toast(err.message, 'error')
    else toast('操作失败', 'error')
  }

  if (isLoading) return <PageLoading />
  if (isError || !data) {
    return (
      <>
        <h1 className="panel-title">应用详情</h1>
        <Card>
          <EmptyState>应用不存在或加载失败</EmptyState>
          <div style={{ textAlign: 'center' }}>
            <Link to="/admin/clients" className="btn btn-ghost btn-sm">
              返回应用列表
            </Link>
          </div>
        </Card>
      </>
    )
  }

  const { client, integration, groups, managerGroups } = data

  return (
    <>
      <p className="panel-sub" style={{ marginBottom: '.5rem' }}>
        <Link to="/admin/clients">← 应用列表</Link>
      </p>
      <h1 className="panel-title">{client.name}</h1>

      <BasicInfoCard client={client} />

      <IntegrationGuide integration={integration} clientId={client.clientId} />

      <EditCard id={id} client={client} afterMutation={afterMutation} onError={onMutationError} />

      <ResetSecretCard id={id} afterMutation={afterMutation} onError={onMutationError} />

      {isAdmin && (
        <ManagersCard
          id={id}
          groups={groups}
          managerGroups={managerGroups}
          afterMutation={afterMutation}
          onError={onMutationError}
        />
      )}

      {isAdmin && (
        <DangerCard
          id={id}
          name={client.name}
          confirm={confirm}
          toast={toast}
          afterDelete={() => {
            qc.invalidateQueries({ queryKey: qk.clients })
            navigate('/admin/clients')
          }}
        />
      )}
    </>
  )
}

// ── Basic info ────────────────────────────────────────────────────────────────
function BasicInfoCard({ client }: { client: AdminClient }) {
  return (
    <div className="detail-section">
      <div className="detail-section-title">基本信息</div>
      <div className="detail-row">
        <div className="detail-key">应用标识</div>
        <div className="detail-val mono">{client.clientId}</div>
      </div>
      <div className="detail-row">
        <div className="detail-key">名称</div>
        <div className="detail-val">{client.name}</div>
      </div>
      <div className="detail-row">
        <div className="detail-key">描述</div>
        <div className="detail-val">
          {client.description || <span style={{ color: 'var(--text2)' }}>（无）</span>}
        </div>
      </div>
      <div className="detail-row">
        <div className="detail-key">权限范围</div>
        <div className="detail-val">
          {client.scopes?.map((s) => (
            <span key={s} className="proj-tag">
              {s}
            </span>
          ))}
        </div>
      </div>
      <div className="detail-row">
        <div className="detail-key">回调地址列表</div>
        <div className="detail-val">
          {client.redirectUris?.map((u) => (
            <div key={u} className="mono" style={{ fontSize: '.82rem' }}>
              {u}
            </div>
          ))}
        </div>
      </div>
      <div className="detail-row">
        <div className="detail-key">基础访问权限</div>
        <div className="detail-val">{BASE_ACCESS_LABELS[client.baseAccess] ?? '兼容模式'}</div>
      </div>
      <div className="detail-row">
        <div className="detail-key">可访问分组</div>
        <div className="detail-val">
          {client.allowedGroups?.length ? (
            client.allowedGroups.map((g) => (
              <span key={g} className="proj-tag">
                {g}
              </span>
            ))
          ) : (
            <span style={{ color: 'var(--text2)' }}>（无限制）</span>
          )}
        </div>
      </div>
      <div className="detail-row">
        <div className="detail-key">创建时间</div>
        <div className="detail-val">{fmt(client.createdAt)}</div>
      </div>
    </div>
  )
}

// ── Integration guide (collapsible) ───────────────────────────────────────────
function IntegrationGuide({
  integration,
  clientId,
}: {
  integration: ClientIntegration
  clientId: string
}) {
  const rows: { field: string; sub?: string; value: string }[] = [
    { field: 'Discovery Document URL', sub: 'Well-Known / Auto-discovery', value: integration.discoveryEndpoint },
    { field: 'Authorization Endpoint', sub: 'authorization_endpoint', value: integration.authorizationEndpoint },
    { field: 'Token Endpoint', sub: 'token_endpoint', value: integration.tokenEndpoint },
    { field: 'Userinfo Endpoint', sub: 'userinfo_endpoint', value: integration.userinfoEndpoint },
    { field: 'JWKS Endpoint', sub: 'jwks_uri', value: integration.jwksEndpoint },
    { field: 'Client ID', value: clientId },
  ]

  return (
    <details className="detail-section" style={{ cursor: 'pointer' }}>
      <summary
        style={{
          fontWeight: 600,
          fontSize: '.95rem',
          listStyle: 'none',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        接入指南{' '}
        <span style={{ fontSize: '.8rem', color: 'var(--text2)', fontWeight: 400 }}>
          （填写到第三方单点登录配置页）▾
        </span>
      </summary>

      <p style={{ fontSize: '.82rem', color: 'var(--text2)', margin: '.8rem 0 1rem' }}>
        将本服务作为身份提供方接入第三方系统时，可按下表填写。 若对方支持自动发现，仅需填写{' '}
        <strong>Discovery Document URL</strong>，其余地址会自动获取。
      </p>

      <div className="table-scroll">
        <table className="data-table" style={{ marginBottom: '1rem' }}>
          <thead>
            <tr>
              <th>Field</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.field}>
                <td>
                  {r.field}
                  {r.sub && (
                    <>
                      <br />
                      <span style={{ fontSize: '.75rem', color: 'var(--text2)' }}>{r.sub}</span>
                    </>
                  )}
                </td>
                <td>
                  <code className="mono break">{r.value}</code>
                </td>
              </tr>
            ))}
            <tr>
              <td>Client Secret</td>
              <td>
                <span style={{ color: 'var(--text2)', fontSize: '.85rem' }}>
                  创建时一次性显示；如已丢失请重置
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </details>
  )
}

// ── Edit form (PATCH) ─────────────────────────────────────────────────────────
function EditCard({
  id,
  client,
  afterMutation,
  onError,
}: {
  id: string
  client: AdminClient
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const [name, setName] = useState(client.name)
  const [description, setDescription] = useState(client.description)
  const [redirectUris, setRedirectUris] = useState((client.redirectUris ?? []).join('\n'))
  const [scopes, setScopes] = useState((client.scopes ?? []).join(' '))
  const [baseAccess, setBaseAccess] = useState(client.baseAccess || 'user')
  const [allowedGroups, setAllowedGroups] = useState((client.allowedGroups ?? []).join(' '))

  // Re-sync when the client refetches after a save.
  useEffect(() => {
    setName(client.name)
    setDescription(client.description)
    setRedirectUris((client.redirectUris ?? []).join('\n'))
    setScopes((client.scopes ?? []).join(' '))
    setBaseAccess(client.baseAccess || 'user')
    setAllowedGroups((client.allowedGroups ?? []).join(' '))
  }, [client])

  const mutation = useMutation({
    // Input field names mirror adminClientUpdateInput: name, description,
    // redirectUris (newline), scopes (space), baseAccess, allowedGroups (space).
    mutationFn: () =>
      api.patch('/admin/clients/' + id, {
        name: name.trim(),
        description: description.trim(),
        redirectUris,
        scopes,
        baseAccess,
        allowedGroups,
      }),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  return (
    <div className="detail-section">
      <div className="detail-section-title">基本配置</div>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          mutation.mutate()
        }}
      >
        <Input label="应用名称" value={name} onChange={(e) => setName(e.target.value)} />
        <Input label="描述" value={description} onChange={(e) => setDescription(e.target.value)} />
        <FormGroup label="回调地址列表（每行一个）">
          <Textarea rows={4} value={redirectUris} onChange={(e) => setRedirectUris(e.target.value)} />
        </FormGroup>
        <Input
          label="权限范围（空格分隔）"
          value={scopes}
          onChange={(e) => setScopes(e.target.value)}
        />

        <hr style={{ margin: '1.2rem 0', border: 'none', borderTop: '1px solid var(--glass-b)' }} />
        <div style={{ fontWeight: 600, fontSize: '.92rem', marginBottom: '.2rem' }}>访问权限配置</div>
        <p style={{ fontSize: '.78rem', color: 'var(--text2)', marginBottom: '.9rem' }}>
          控制哪些用户可通过此应用进行单点登录（SSO）。
        </p>

        <Select
          label="基础访问权限"
          value={baseAccess}
          onChange={(e) => setBaseAccess(e.target.value)}
        >
          <option value="legacy">兼容模式（有分组则仅按分组，无分组则全部可访问）</option>
          <option value="user">所有已登录用户</option>
          <option value="member">成员及以上</option>
          <option value="admin">仅管理员</option>
          <option value="none">不启用基础权限（仅分组）</option>
        </Select>
        <FormGroup
          label="可访问分组（空格分隔分组代号）"
          hint="命中任意一个分组即可访问；自定义分组代号请在「分组管理」页面查看。"
        >
          <Input
            value={allowedGroups}
            onChange={(e) => setAllowedGroups(e.target.value)}
            placeholder="留空则仅凭基础访问权限判断"
          />
        </FormGroup>

        <Button type="submit" size="sm" loading={mutation.isPending}>
          保存修改
        </Button>
      </form>
    </div>
  )
}

// ── Reset secret (one-time, shown in a modal) ─────────────────────────────────
function ResetSecretCard({
  id,
  afterMutation,
  onError,
}: {
  id: string
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const confirm = useConfirm()
  const { toast } = useToast()
  const [newSecret, setNewSecret] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const mutation = useMutation({
    mutationFn: () => api.post<{ clientSecret: string }>('/admin/clients/' + id + '/reset-secret'),
    onSuccess: (res) => {
      setNewSecret(res.data.clientSecret)
      afterMutation(res.flash)
    },
    onError,
  })

  async function onReset() {
    const ok = await confirm({
      title: '重置应用密钥',
      message: '重置后旧密钥立即失效，所有使用旧密钥的应用都需要更新。',
      confirmLabel: '重置',
      icon: '🔑',
    })
    if (ok) mutation.mutate()
  }

  async function copySecret() {
    if (!newSecret) return
    try {
      await navigator.clipboard.writeText(newSecret)
      setCopied(true)
      toast('已复制应用密钥', 'success')
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast('复制失败，请手动选择复制', 'error')
    }
  }

  return (
    <div className="detail-section">
      <div className="detail-section-title">应用密钥</div>
      <p style={{ fontSize: '.82rem', color: 'var(--text2)', marginBottom: '.8rem' }}>
        重置后旧密钥立即失效，新密钥仅显示一次。
      </p>
      <Button variant="ghost" size="sm" onClick={onReset} loading={mutation.isPending}>
        重置应用密钥
      </Button>

      <Modal
        open={!!newSecret}
        onClose={() => setNewSecret(null)}
        title="应用密钥已重置"
        footer={
          <Button size="sm" onClick={() => setNewSecret(null)}>
            我已保存
          </Button>
        }
      >
        <div className="secret-box">
          <p style={{ fontWeight: 600, marginBottom: '.6rem' }}>
            ⚠️ 新应用密钥（仅显示一次，请立即复制保存）
          </p>
          <div className="secret-val" style={{ marginBottom: '.8rem' }}>
            {newSecret}
          </div>
          <Button size="sm" onClick={copySecret}>
            {copied ? '已复制' : '复制密钥'}
          </Button>
        </div>
        <p style={{ fontSize: '.85rem', color: 'var(--text2)', marginTop: '1rem' }}>
          旧密钥已立即失效。所有使用旧密钥的应用都需要更新配置。
        </p>
      </Modal>
    </div>
  )
}

// ── Set managers (admin only) ─────────────────────────────────────────────────
function ManagersCard({
  id,
  groups,
  managerGroups,
  afterMutation,
  onError,
}: {
  id: string
  groups: GroupDTO[]
  managerGroups: string[]
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const [selected, setSelected] = useState<string[]>(managerGroups ?? [])

  useEffect(() => {
    setSelected(managerGroups ?? [])
  }, [managerGroups])

  const mutation = useMutation({
    // adminClientSetManagersInput: managerGroups []string.
    mutationFn: () => api.post('/admin/clients/' + id + '/managers', { managerGroups: selected }),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  function onSelectChange(e: React.ChangeEvent<HTMLSelectElement>) {
    setSelected(Array.from(e.target.selectedOptions, (o) => o.value))
  }

  return (
    <div className="detail-section">
      <div className="detail-section-title">应用管理员组</div>
      <p style={{ fontSize: '.82rem', color: 'var(--text2)', marginBottom: '.8rem' }}>
        设置哪些分组的成员可以管理此应用（编辑配置、重置密钥）。留空则所有拥有「管理应用」权限的用户均可管理。
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          mutation.mutate()
        }}
      >
        <FormGroup hint="按住 Ctrl / Cmd 可多选；不选即清除限制">
          <select
            className="form-control"
            multiple
            size={5}
            style={{ height: 'auto' }}
            value={selected}
            onChange={onSelectChange}
          >
            {groups.map((g) => (
              <option key={g.id} value={g.name}>
                {g.label || g.name} ({g.name})
              </option>
            ))}
          </select>
        </FormGroup>
        <Button variant="ghost" size="sm" type="submit" loading={mutation.isPending}>
          保存管理员组
        </Button>
      </form>
    </div>
  )
}

// ── Danger zone (delete, admin only) ──────────────────────────────────────────
function DangerCard({
  id,
  name,
  confirm,
  toast,
  afterDelete,
}: {
  id: string
  name: string
  confirm: ReturnType<typeof useConfirm>
  toast: ReturnType<typeof useToast>['toast']
  afterDelete: () => void
}) {
  const del = useMutation({
    mutationFn: () => api.del('/admin/clients/' + id),
    onSuccess: (res) => {
      toast(res.flash || '已删除', 'success')
      afterDelete()
    },
    onError: (err) => {
      if (err instanceof ApiError) toast(err.message, 'error')
      else toast('删除失败', 'error')
    },
  })

  async function onDelete() {
    const ok = await confirm({
      title: '删除应用',
      message: `确定要删除应用 ${name} 吗？删除后所有令牌将失效，此操作不可撤销。`,
      confirmLabel: '删除此应用',
      danger: true,
    })
    if (ok) del.mutate()
  }

  return (
    <div className="detail-section" style={{ borderColor: '#fecaca' }}>
      <div className="detail-section-title" style={{ color: '#dc2626' }}>
        危险操作
      </div>
      <div style={{ display: 'flex', gap: '.8rem', flexWrap: 'wrap' }}>
        <Button variant="danger" size="sm" onClick={onDelete} loading={del.isPending}>
          删除此应用
        </Button>
      </div>
    </div>
  )
}
