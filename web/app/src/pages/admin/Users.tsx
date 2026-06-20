import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, RoleBadge, EmptyState, PageLoading, StatusText } from '@/components/ui'
import { Input, Select, Checkbox } from '@/components/form'
import { Modal } from '@/components/Modal'
import { Pagination } from '@/components/Pagination'
import { useToast } from '@/providers/ToastProvider'
import { useAuth } from '@/providers/AuthProvider'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import type { User } from '@/api/types'

interface CustomRole {
  name: string
  label: string
  permissions: string[]
}

interface UsersResponse {
  users: User[]
  total: number
  page: number
  pages: number
  pageSize: number
  pageSizeOpts: number[]
  customRoles: CustomRole[]
  isSysAdmin: boolean
  filters: { q: string; role: string; active: string; verified: string }
}

interface UserDetailResponse {
  user: User
  isSysAdmin: boolean
}

const ROLE_LABELS: Record<string, string> = { admin: '管理员', member: '成员', user: '用户' }

function roleLabel(role: string, customRoles: CustomRole[]): string {
  const cr = customRoles.find((r) => r.name === role)
  if (cr) return cr.label || cr.name
  return ROLE_LABELS[role] ?? role
}

export default function Users() {
  const [params, setParams] = useSearchParams()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { isSystemAdmin } = useAuth()

  // ── Filter state lives in the URL ──────────────────────────────────────────
  const urlQ = params.get('q') ?? ''
  const role = params.get('role') ?? ''
  const active = params.get('active') ?? ''
  const verified = params.get('verified') ?? ''
  const pageSize = params.get('page_size') ?? ''
  const page = Math.max(1, parseInt(params.get('page') ?? '1', 10) || 1)

  // Local search box value mirrors the URL but updates immediately; the URL is
  // only updated once the value settles (debounced) so paging URLs stay clean.
  const [search, setSearch] = useState(urlQ)
  const debouncedSearch = useDebouncedValue(search, 300)

  // Keep the input in sync when the URL changes externally (e.g. reset link).
  useEffect(() => {
    setSearch(urlQ)
  }, [urlQ])

  // Push the debounced search term into the URL (resetting page) when it differs.
  useEffect(() => {
    if (debouncedSearch === urlQ) return
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        if (debouncedSearch) next.set('q', debouncedSearch)
        else next.delete('q')
        next.delete('page')
        return next
      },
      { replace: true },
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch])

  // setParam updates one filter and resets the page to 1 (deletes the param).
  function setParam(key: string, value: string | number | null) {
    setParams((prev) => {
      const next = new URLSearchParams(prev)
      if (value === null || value === '') next.delete(key)
      else next.set(key, String(value))
      if (key !== 'page') next.delete('page')
      return next
    })
  }

  // ── Query (URL-derived key so each combination is cached) ───────────────────
  const filters = { q: urlQ, role, active, verified, page_size: pageSize, page }
  const queryString = (() => {
    const sp = new URLSearchParams()
    if (urlQ) sp.set('q', urlQ)
    if (role) sp.set('role', role)
    if (active) sp.set('active', active)
    if (verified) sp.set('verified', verified)
    if (pageSize) sp.set('page_size', pageSize)
    if (page > 1) sp.set('page', String(page))
    return sp.toString()
  })()

  const { data, isLoading, isFetching, isError } = useQuery({
    queryKey: qk.users(filters),
    queryFn: () => api.get<UsersResponse>('/admin/users?' + queryString),
    placeholderData: keepPreviousData,
  })

  const customRoles = data?.customRoles ?? []

  // ── Detail modal ────────────────────────────────────────────────────────────
  const [detailId, setDetailId] = useState<string | null>(null)

  // ── Create modal ────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false)

  const hasActiveFilters = !!(urlQ || role || active || verified || pageSize)

  if (isLoading && !data) return <PageLoading />

  const total = data?.total ?? 0
  const pages = data?.pages ?? 1
  const users = data?.users ?? []

  return (
    <>
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: '1rem',
          flexWrap: 'wrap',
        }}
      >
        <div>
          <h1 className="panel-title">用户管理</h1>
          <p className="panel-sub">
            共 {total} 位用户，第 {data?.page ?? page} / {pages} 页
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>+ 新增用户</Button>
      </div>

      {/* ── Filters ─────────────────────────────────────────────────────────── */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: '.75rem',
            alignItems: 'end',
          }}
        >
          <Input
            label="搜索"
            placeholder="邮箱或名称…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <Select label="角色" value={role} onChange={(e) => setParam('role', e.target.value)}>
            <option value="">全部</option>
            <option value="user">用户</option>
            <option value="member">成员</option>
            <option value="admin">管理员</option>
            {customRoles.map((r) => (
              <option key={r.name} value={r.name}>
                {r.label || r.name}
              </option>
            ))}
          </Select>
          <Select label="状态" value={active} onChange={(e) => setParam('active', e.target.value)}>
            <option value="">全部</option>
            <option value="1">启用</option>
            <option value="0">停用</option>
          </Select>
          <Select label="邮箱验证" value={verified} onChange={(e) => setParam('verified', e.target.value)}>
            <option value="">全部</option>
            <option value="1">已验证</option>
            <option value="0">未验证</option>
          </Select>
          <Select label="每页" value={pageSize} onChange={(e) => setParam('page_size', e.target.value)}>
            <option value="">默认 (50)</option>
            {(data?.pageSizeOpts ?? [10, 20, 50, 100, 200]).map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </Select>
        </div>
        {hasActiveFilters && (
          <div style={{ marginTop: '.75rem' }}>
            <Link to="/admin/users" className="btn btn-ghost btn-sm">
              重置筛选
            </Link>
          </div>
        )}
      </div>

      {/* Top progress bar while fetching (not first load). */}
      {isFetching && <div className="is-fetching-bar" />}

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载用户列表失败，请稍后重试</EmptyState>
        ) : users.length === 0 ? (
          <EmptyState>没有符合条件的用户</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>邮箱</th>
                  <th>名称</th>
                  <th>角色</th>
                  <th>状态</th>
                  <th>邮箱验证</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.email}</td>
                    <td>{u.displayName || '—'}</td>
                    <td>
                      <RoleBadge role={u.role} label={roleLabel(u.role, customRoles)} />
                    </td>
                    <td>
                      <StatusText active={u.active} />
                    </td>
                    <td>
                      <StatusText active={u.emailVerified} on="已验证" off="未验证" />
                    </td>
                    <td>
                      <div style={{ display: 'inline-flex', gap: '.4rem', flexWrap: 'wrap' }}>
                        <Button variant="ghost" size="sm" onClick={() => setDetailId(u.id)}>
                          详情
                        </Button>
                        <Link to={`/admin/users/${u.id}`} className="btn btn-ghost btn-sm">
                          完整页
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination page={data?.page ?? page} pages={pages} onPage={(p) => setParam('page', p)} />
      </div>

      {detailId && (
        <UserDetailModal
          id={detailId}
          customRoles={customRoles}
          onClose={() => setDetailId(null)}
        />
      )}

      <CreateUserModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        isSysAdmin={isSystemAdmin || data?.isSysAdmin || false}
        customRoles={customRoles}
        onCreated={(flash) => {
          qc.invalidateQueries({ queryKey: ['admin', 'users'] })
          toast(flash || '已创建用户', 'success')
          setCreateOpen(false)
        }}
      />
    </>
  )
}

// ── Detail modal (lightweight; full page lives at /admin/users/:id) ───────────
function UserDetailModal({
  id,
  customRoles,
  onClose,
}: {
  id: string
  customRoles: CustomRole[]
  onClose: () => void
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.user(id),
    queryFn: () => api.get<UserDetailResponse>('/admin/users/' + id),
  })
  const u = data?.user

  return (
    <Modal
      open
      onClose={onClose}
      title="用户详情"
      footer={
        <>
          <Link to={`/admin/users/${id}`} className="btn btn-primary btn-sm">
            打开完整页
          </Link>
          <Button variant="ghost" size="sm" onClick={onClose}>
            关闭
          </Button>
        </>
      }
    >
      {isLoading ? (
        <PageLoading />
      ) : isError || !u ? (
        <EmptyState>加载用户详情失败</EmptyState>
      ) : (
        <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '.5rem 1rem', margin: 0 }}>
          <dt style={{ color: 'var(--text2)' }}>邮箱</dt>
          <dd style={{ margin: 0 }}>{u.email}</dd>
          <dt style={{ color: 'var(--text2)' }}>名称</dt>
          <dd style={{ margin: 0 }}>{u.displayName || '—'}</dd>
          <dt style={{ color: 'var(--text2)' }}>角色</dt>
          <dd style={{ margin: 0 }}>
            <RoleBadge role={u.role} label={roleLabel(u.role, customRoles)} />
          </dd>
          <dt style={{ color: 'var(--text2)' }}>状态</dt>
          <dd style={{ margin: 0 }}>
            <StatusText active={u.active} />
          </dd>
          <dt style={{ color: 'var(--text2)' }}>邮箱验证</dt>
          <dd style={{ margin: 0 }}>
            <StatusText active={u.emailVerified} on="已验证" off="未验证" />
          </dd>
          <dt style={{ color: 'var(--text2)' }}>双重验证</dt>
          <dd style={{ margin: 0 }}>
            <StatusText active={u.totpEnabled} on="已开启" off="未开启" />
          </dd>
          <dt style={{ color: 'var(--text2)' }}>强制改密</dt>
          <dd style={{ margin: 0 }}>{u.requirePasswordChange ? '是' : '否'}</dd>
          <dt style={{ color: 'var(--text2)' }}>创建时间</dt>
          <dd style={{ margin: 0 }}>{new Date(u.createdAt).toLocaleString()}</dd>
        </dl>
      )}
    </Modal>
  )
}

// ── Create modal ──────────────────────────────────────────────────────────────
function CreateUserModal({
  open,
  onClose,
  isSysAdmin,
  customRoles,
  onCreated,
}: {
  open: boolean
  onClose: () => void
  isSysAdmin: boolean
  customRoles: CustomRole[]
  onCreated: (flash?: string) => void
}) {
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('user')
  const [requirePasswordChange, setRequirePasswordChange] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  // Reset the form whenever the modal opens.
  useEffect(() => {
    if (open) {
      setEmail('')
      setDisplayName('')
      setPassword('')
      setRole('user')
      setRequirePasswordChange(false)
      setFieldErrors({})
    }
  }, [open])

  const mutation = useMutation({
    mutationFn: () =>
      api.post<User>('/admin/users', {
        email: email.trim(),
        displayName: displayName.trim(),
        password,
        role,
        requirePasswordChange,
      }),
    onSuccess: (res) => onCreated(res.flash),
    onError: (err) => {
      if (err instanceof ApiError && err.fieldErrors) setFieldErrors(err.fieldErrors)
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (!email.trim()) errs.email = '请输入邮箱'
    if (password.length < 8) errs.password = '密码至少需要 8 位'
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    mutation.mutate()
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="新增用户"
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={onClose} type="button">
            取消
          </Button>
          <Button size="sm" onClick={submit} loading={mutation.isPending} type="submit">
            创建
          </Button>
        </>
      }
    >
      <form onSubmit={submit}>
        <Input
          label="邮箱"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          error={fieldErrors.email}
          autoComplete="off"
        />
        <Input
          label="名称"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          error={fieldErrors.displayName}
        />
        <Input
          label="密码"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          error={fieldErrors.password}
          hint="至少 8 位"
          autoComplete="new-password"
        />
        <Select label="角色" value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="user">用户</option>
          <option value="member">成员</option>
          {isSysAdmin && <option value="admin">管理员</option>}
          {customRoles.map((r) => (
            <option key={r.name} value={r.name}>
              {r.label || r.name}
            </option>
          ))}
        </Select>
        <div style={{ marginTop: '.5rem' }}>
          <Checkbox
            label="要求首次登录修改密码"
            checked={requirePasswordChange}
            onChange={(e) => setRequirePasswordChange(e.target.checked)}
          />
        </div>
        {/* Hidden submit so Enter submits the form. */}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}
