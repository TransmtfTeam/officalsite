import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card, RoleBadge, EmptyState, PageLoading, StatusText } from '@/components/ui'
import { Input, Select, Checkbox } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'
import { useAuth } from '@/providers/AuthProvider'
import type { User } from '@/api/types'

interface CustomRole {
  name: string
  label: string
  permissions: string[]
}
interface GroupDTO {
  id: string
  name: string
  label: string
  createdAt: string
}
interface SessionDTO {
  id: string
  createdAt: string
  expiresAt: string
}
interface TokenDTO {
  id: string
  clientId: string
  scopes: string[]
  expiresAt: string
}
interface PasskeyDTO {
  id: string
  name: string
  createdAt: string
}

interface UserDetailResponse {
  user: User
  sessions: SessionDTO[]
  accessTokens: TokenDTO[]
  refreshTokens: TokenDTO[]
  passkeys: PasskeyDTO[]
  groups: GroupDTO[]
  customRoles: CustomRole[]
  isSysAdmin: boolean
}

const ROLE_LABELS: Record<string, string> = { admin: '管理员', member: '成员', user: '用户' }

function roleLabel(role: string, customRoles: CustomRole[]): string {
  const cr = customRoles.find((r) => r.name === role)
  if (cr) return cr.label || cr.name
  return ROLE_LABELS[role] ?? role
}

function fmt(ts: string): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}

export default function UserDetail() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()
  const navigate = useNavigate()
  const { isSystemAdmin } = useAuth()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.user(id),
    queryFn: () => api.get<UserDetailResponse>('/admin/users/' + id),
    enabled: !!id,
  })

  // Helper to run a mutation, surface flash + errors, then refresh caches.
  function afterMutation(flash?: string) {
    qc.invalidateQueries({ queryKey: qk.user(id) })
    qc.invalidateQueries({ queryKey: ['admin', 'users'] })
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
        <h1 className="panel-title">用户详情</h1>
        <Card>
          <EmptyState>用户不存在或加载失败</EmptyState>
          <div style={{ textAlign: 'center' }}>
            <Link to="/admin/users" className="btn btn-ghost btn-sm">
              返回用户列表
            </Link>
          </div>
        </Card>
      </>
    )
  }

  const { user, sessions, accessTokens, refreshTokens, passkeys, groups, customRoles } = data
  const canManageRole = isSystemAdmin || data.isSysAdmin

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: '.75rem', flexWrap: 'wrap' }}>
        <h1 className="panel-title" style={{ marginBottom: 0 }}>
          {user.displayName || user.email}
        </h1>
        <RoleBadge role={user.role} label={roleLabel(user.role, customRoles)} />
      </div>
      <p className="panel-sub">
        <Link to="/admin/users">← 返回用户列表</Link>
      </p>

      <AccountInfoCard user={user} customRoles={customRoles} />

      <EditCard
        id={id}
        user={user}
        customRoles={customRoles}
        canManageRole={canManageRole}
        afterMutation={afterMutation}
        onError={onMutationError}
      />

      <SecurityCard
        id={id}
        user={user}
        afterMutation={afterMutation}
        onError={onMutationError}
      />

      <GroupsCard id={id} groups={groups} afterMutation={afterMutation} onError={onMutationError} />

      <SessionsCard id={id} sessions={sessions} afterMutation={afterMutation} onError={onMutationError} />

      <TokensCard
        id={id}
        accessTokens={accessTokens}
        refreshTokens={refreshTokens}
        afterMutation={afterMutation}
        onError={onMutationError}
      />

      <PasskeysCard id={id} passkeys={passkeys} afterMutation={afterMutation} onError={onMutationError} />

      <DangerCard
        id={id}
        user={user}
        confirm={confirm}
        toast={toast}
        afterDelete={() => {
          qc.invalidateQueries({ queryKey: ['admin', 'users'] })
          navigate('/admin/users')
        }}
      />
    </>
  )
}

// ── Account info ──────────────────────────────────────────────────────────────
function AccountInfoCard({ user, customRoles }: { user: User; customRoles: CustomRole[] }) {
  return (
    <Card>
      <h2 className="form-panel-title">账户信息</h2>
      <dl className="kv">
        <dt>ID</dt>
        <dd style={{ fontFamily: 'monospace', fontSize: '.85rem' }}>{user.id}</dd>
        <dt>邮箱</dt>
        <dd>{user.email}</dd>
        <dt>名称</dt>
        <dd>{user.displayName || '—'}</dd>
        <dt>角色</dt>
        <dd>
          <RoleBadge role={user.role} label={roleLabel(user.role, customRoles)} />
        </dd>
        <dt>状态</dt>
        <dd>
          <StatusText active={user.active} />
        </dd>
        <dt>邮箱验证</dt>
        <dd>
          <StatusText active={user.emailVerified} on="已验证" off="未验证" />
        </dd>
        <dt>双重验证</dt>
        <dd>
          <StatusText active={user.totpEnabled} on="已开启" off="未开启" />
        </dd>
        <dt>强制改密</dt>
        <dd>{user.requirePasswordChange ? '是' : '否'}</dd>
        <dt>创建时间</dt>
        <dd>{fmt(user.createdAt)}</dd>
      </dl>
    </Card>
  )
}

// ── Edit form ─────────────────────────────────────────────────────────────────
function EditCard({
  id,
  user,
  customRoles,
  canManageRole,
  afterMutation,
  onError,
}: {
  id: string
  user: User
  customRoles: CustomRole[]
  canManageRole: boolean
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const [displayName, setDisplayName] = useState(user.displayName)
  const [role, setRole] = useState(user.role)
  const [active, setActive] = useState(user.active)

  // Re-sync when the underlying user changes (after a successful save refetch).
  useEffect(() => {
    setDisplayName(user.displayName)
    setRole(user.role)
    setActive(user.active)
  }, [user.displayName, user.role, user.active])

  const mutation = useMutation({
    mutationFn: () =>
      api.patch('/admin/users/' + id, { displayName: displayName.trim(), role, active }),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  return (
    <Card>
      <h2 className="form-panel-title">编辑账户</h2>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          mutation.mutate()
        }}
      >
        <Input label="名称" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        <Select
          label="角色"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          disabled={!canManageRole && role === 'admin'}
        >
          <option value="user">用户</option>
          <option value="member">成员</option>
          {(canManageRole || user.role === 'admin') && <option value="admin">管理员</option>}
          {customRoles.map((r) => (
            <option key={r.name} value={r.name}>
              {r.label || r.name}
            </option>
          ))}
        </Select>
        <div style={{ margin: '.5rem 0 1rem' }}>
          <Checkbox label="账户启用" checked={active} onChange={(e) => setActive(e.target.checked)} />
        </div>
        <Button type="submit" loading={mutation.isPending}>
          保存修改
        </Button>
      </form>
    </Card>
  )
}

// ── Security actions: reset password, disable 2FA, verify/unverify email ──────
function SecurityCard({
  id,
  user,
  afterMutation,
  onError,
}: {
  id: string
  user: User
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const [newPassword, setNewPassword] = useState('')
  const [requirePasswordChange, setRequirePasswordChange] = useState(true)
  const [pwError, setPwError] = useState('')

  const resetPw = useMutation({
    mutationFn: () =>
      api.post('/admin/users/' + id + '/reset-password', {
        newPassword,
        requirePasswordChange,
      }),
    onSuccess: (res) => {
      setNewPassword('')
      afterMutation(res.flash)
    },
    onError,
  })

  const disable2fa = useMutation({
    mutationFn: () => api.post('/admin/users/' + id + '/disable-2fa'),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  const verifyEmail = useMutation({
    mutationFn: (verified: boolean) =>
      api.post('/admin/users/' + id + (verified ? '/verify-email' : '/unverify-email')),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  return (
    <Card>
      <h2 className="form-panel-title">安全与验证</h2>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (newPassword.length < 8) {
            setPwError('密码至少需要 8 位')
            return
          }
          setPwError('')
          resetPw.mutate()
        }}
        style={{ marginBottom: '1.2rem' }}
      >
        <Input
          label="重置密码"
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          error={pwError}
          hint="至少 8 位；保存后会向用户发送新密码邮件"
          autoComplete="new-password"
        />
        <div style={{ margin: '.4rem 0 .8rem' }}>
          <Checkbox
            label="要求用户下次登录修改密码"
            checked={requirePasswordChange}
            onChange={(e) => setRequirePasswordChange(e.target.checked)}
          />
        </div>
        <Button type="submit" loading={resetPw.isPending} disabled={!newPassword}>
          重置密码
        </Button>
      </form>

      <div style={{ display: 'flex', gap: '.6rem', flexWrap: 'wrap' }}>
        <Button
          variant="ghost"
          onClick={() => disable2fa.mutate()}
          loading={disable2fa.isPending}
          disabled={!user.totpEnabled}
        >
          关闭双重验证
        </Button>
        {user.emailVerified ? (
          <Button
            variant="ghost"
            onClick={() => verifyEmail.mutate(false)}
            loading={verifyEmail.isPending}
          >
            设为未验证
          </Button>
        ) : (
          <Button
            variant="ghost"
            onClick={() => verifyEmail.mutate(true)}
            loading={verifyEmail.isPending}
          >
            标记邮箱已验证
          </Button>
        )}
      </div>
    </Card>
  )
}

// ── Groups ────────────────────────────────────────────────────────────────────
function GroupsCard({
  id,
  groups,
  afterMutation,
  onError,
}: {
  id: string
  groups: GroupDTO[]
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const [groupId, setGroupId] = useState('')

  // All groups (to populate the add-group <select>, minus ones already joined).
  const { data: allGroups } = useQuery({
    queryKey: qk.groups,
    queryFn: () => api.get<GroupDTO[]>('/admin/groups'),
  })
  const joined = new Set(groups.map((g) => g.id))
  const available = (allGroups ?? []).filter((g) => !joined.has(g.id))

  const addGroup = useMutation({
    mutationFn: () => api.post('/admin/users/' + id + '/groups', { groupId }),
    onSuccess: (res) => {
      setGroupId('')
      afterMutation(res.flash)
    },
    onError,
  })

  const removeGroup = useMutation({
    mutationFn: (gid: string) => api.del('/admin/users/' + id + '/groups/' + gid),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  return (
    <Card>
      <h2 className="form-panel-title">所属分组</h2>
      {groups.length === 0 ? (
        <p style={{ color: 'var(--text2)', margin: '0 0 1rem' }}>暂无分组</p>
      ) : (
        <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          {groups.map((g) => (
            <span
              key={g.id}
              className="role-badge role-user"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '.35rem' }}
            >
              {g.label || g.name}
              <button
                type="button"
                aria-label="移除分组"
                onClick={() => removeGroup.mutate(g.id)}
                disabled={removeGroup.isPending}
                style={{ background: 'none', border: 0, cursor: 'pointer', color: 'inherit', fontSize: '1rem', lineHeight: 1 }}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (groupId) addGroup.mutate()
        }}
        className="inline-fields"
      >
        <div className="field-grow">
          <Select label="加入分组" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">选择分组…</option>
            {available.map((g) => (
              <option key={g.id} value={g.id}>
                {g.label || g.name}
              </option>
            ))}
          </Select>
        </div>
        <Button type="submit" disabled={!groupId} loading={addGroup.isPending}>
          加入
        </Button>
      </form>
    </Card>
  )
}

// ── Sessions ──────────────────────────────────────────────────────────────────
function SessionsCard({
  id,
  sessions,
  afterMutation,
  onError,
}: {
  id: string
  sessions: SessionDTO[]
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const revoke = useMutation({
    mutationFn: (sid: string) => api.del('/admin/users/' + id + '/sessions/' + sid),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  return (
    <Card>
      <h2 className="form-panel-title">活动会话（{sessions.length}）</h2>
      {sessions.length === 0 ? (
        <p style={{ color: 'var(--text2)', margin: 0 }}>暂无活动会话</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>会话 ID</th>
                <th>创建时间</th>
                <th>过期时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id}>
                  <td style={{ fontFamily: 'monospace', fontSize: '.82rem' }}>{s.id}</td>
                  <td>{fmt(s.createdAt)}</td>
                  <td>{fmt(s.expiresAt)}</td>
                  <td>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => revoke.mutate(s.id)}
                      loading={revoke.isPending}
                    >
                      撤销
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ── Tokens (access + refresh) ─────────────────────────────────────────────────
function TokensCard({
  id,
  accessTokens,
  refreshTokens,
  afterMutation,
  onError,
}: {
  id: string
  accessTokens: TokenDTO[]
  refreshTokens: TokenDTO[]
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const revoke = useMutation({
    mutationFn: ({ tid, type }: { tid: string; type: 'access' | 'refresh' }) =>
      api.del('/admin/users/' + id + '/tokens/' + tid, { type }),
    onSuccess: (res) => afterMutation(res.flash),
    onError,
  })

  const rows: { token: TokenDTO; type: 'access' | 'refresh' }[] = [
    ...accessTokens.map((t) => ({ token: t, type: 'access' as const })),
    ...refreshTokens.map((t) => ({ token: t, type: 'refresh' as const })),
  ]

  return (
    <Card>
      <h2 className="form-panel-title">令牌（{rows.length}）</h2>
      {rows.length === 0 ? (
        <p style={{ color: 'var(--text2)', margin: 0 }}>暂无令牌</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>类型</th>
                <th>客户端</th>
                <th>授权范围</th>
                <th>过期时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ token, type }) => (
                <tr key={type + ':' + token.id}>
                  <td>{type === 'access' ? '访问令牌' : '刷新令牌'}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '.82rem' }}>{token.clientId}</td>
                  <td>{token.scopes?.join(' ') || '—'}</td>
                  <td>{fmt(token.expiresAt)}</td>
                  <td>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => revoke.mutate({ tid: token.id, type })}
                      loading={revoke.isPending}
                    >
                      撤销
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ── Passkeys ──────────────────────────────────────────────────────────────────
function PasskeysCard({
  id,
  passkeys,
  afterMutation,
  onError,
}: {
  id: string
  passkeys: PasskeyDTO[]
  afterMutation: (flash?: string) => void
  onError: (err: unknown) => void
}) {
  const remove = useMutation({
    mutationFn: (pkid: string) => api.del('/admin/users/' + id + '/passkeys/' + pkid),
    onSuccess: () => afterMutation('已删除通行密钥'),
    onError,
  })

  return (
    <Card>
      <h2 className="form-panel-title">通行密钥（{passkeys.length}）</h2>
      {passkeys.length === 0 ? (
        <p style={{ color: 'var(--text2)', margin: 0 }}>暂无通行密钥</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((p) => (
                <tr key={p.id}>
                  <td>{p.name || '—'}</td>
                  <td>{fmt(p.createdAt)}</td>
                  <td>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => remove.mutate(p.id)}
                      loading={remove.isPending}
                    >
                      删除
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ── Danger zone: delete with exact-email confirmation ─────────────────────────
function DangerCard({
  id,
  user,
  confirm,
  toast,
  afterDelete,
}: {
  id: string
  user: User
  confirm: ReturnType<typeof useConfirm>
  toast: ReturnType<typeof useToast>['toast']
  afterDelete: () => void
}) {
  const [confirmEmail, setConfirmEmail] = useState('')
  const matches = confirmEmail.trim().toLowerCase() === user.email.toLowerCase()

  const del = useMutation({
    mutationFn: () => api.del('/admin/users/' + id, { confirmEmail: confirmEmail.trim() }),
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
    if (!matches) return
    const ok = await confirm({
      title: '删除用户',
      message: `确定要永久删除用户 ${user.email} 吗？此操作不可撤销。`,
      confirmLabel: '永久删除',
      danger: true,
    })
    if (ok) del.mutate()
  }

  return (
    <Card style={{ borderColor: '#fecaca' }}>
      <h2 className="form-panel-title" style={{ color: '#dc2626' }}>
        危险操作
      </h2>
      <p style={{ color: 'var(--text2)', margin: '0 0 .8rem', fontSize: '.88rem' }}>
        删除用户将一并清除其会话、令牌与通行密钥。请输入用户邮箱 <strong>{user.email}</strong> 以确认。
      </p>
      <Input
        label="确认邮箱"
        value={confirmEmail}
        onChange={(e) => setConfirmEmail(e.target.value)}
        placeholder={user.email}
        autoComplete="off"
      />
      <Button variant="danger" disabled={!matches} loading={del.isPending} onClick={onDelete}>
        删除用户
      </Button>
    </Card>
  )
}
