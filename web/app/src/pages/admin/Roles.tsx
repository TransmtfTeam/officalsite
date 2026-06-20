import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, Card, EmptyState, PageLoading } from '@/components/ui'
import { Input } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'

// adminRoleDTO from internal/server/api_admin_misc.go (camelCase JSON).
interface AdminRole {
  name: string
  label: string
  permissions: string[]
  createdAt: string
}

// allPermissions catalog entries from handlers_admin.go ({name,label,desc}).
interface Permission {
  name: string
  label: string
  desc: string
}

interface RolesResponse {
  roles: AdminRole[]
  allPermissions: Permission[]
}

export default function Roles() {
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.roles,
    queryFn: () => api.get<RolesResponse>('/admin/roles'),
  })

  if (isLoading) return <PageLoading />

  const roles = data?.roles ?? []
  const allPermissions = data?.allPermissions ?? []

  return (
    <>
      <h1 className="panel-title">角色管理</h1>
      <p className="panel-sub">创建自定义角色，并为其分配权限。内置角色（管理员 / 成员 / 用户）不可删除。</p>

      <CreateRoleCard allPermissions={allPermissions} />

      <Card style={{ padding: 0, marginTop: '1rem' }}>
        {isError ? (
          <EmptyState>加载角色列表失败，请稍后重试</EmptyState>
        ) : roles.length === 0 ? (
          <EmptyState>暂无自定义角色，请使用上方表单创建</EmptyState>
        ) : (
          <RolesTable roles={roles} allPermissions={allPermissions} />
        )}
      </Card>
    </>
  )
}

// ── Create role form ──────────────────────────────────────────────────────────
function CreateRoleCard({ allPermissions }: { allPermissions: Permission[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()

  const [name, setName] = useState('')
  const [label, setLabel] = useState('')
  const [permissions, setPermissions] = useState<string[]>([])
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  function togglePerm(perm: string, checked: boolean) {
    setPermissions((cur) => (checked ? [...cur, perm] : cur.filter((p) => p !== perm)))
  }

  const mutation = useMutation({
    // Field names mirror adminRoleCreateInput: name, label, permissions[].
    mutationFn: () =>
      api.post<AdminRole>('/admin/roles', {
        name: name.trim().toLowerCase(),
        label: label.trim(),
        permissions,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.roles })
      toast(res.flash || '角色已创建', 'success')
      setName('')
      setLabel('')
      setPermissions([])
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
    if (!name.trim()) errs.name = '角色名称不能为空'
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    mutation.mutate()
  }

  return (
    <Card>
      <div className="detail-section-title">创建角色</div>
      <form onSubmit={submit}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <Input
            label={
              <>
                角色名称 <span style={{ color: '#dc2626' }}>*</span>
              </>
            }
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={fieldErrors.name}
            hint="作为系统标识，建议使用小写英文（保存时会自动转为小写）"
            placeholder="editor"
          />
          <Input
            label="显示名称"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="编辑"
          />
        </div>

        <div className="form-group">
          <label className="form-label">权限</label>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
              gap: '.6rem',
            }}
          >
            {allPermissions.map((p) => (
              <label
                key={p.name}
                style={{ display: 'flex', alignItems: 'flex-start', gap: '.5rem', cursor: 'pointer' }}
              >
                <input
                  type="checkbox"
                  checked={permissions.includes(p.name)}
                  onChange={(e) => togglePerm(p.name, e.target.checked)}
                  style={{ marginTop: '.2rem' }}
                />
                <span>
                  <span style={{ fontSize: '.88rem', fontWeight: 500 }}>{p.label}</span>
                  <span style={{ display: 'block', fontSize: '.75rem', color: 'var(--text2)' }}>{p.desc}</span>
                </span>
              </label>
            ))}
          </div>
        </div>

        <div style={{ marginTop: '.6rem' }}>
          <Button type="submit" loading={mutation.isPending}>
            创建角色
          </Button>
        </div>
      </form>
    </Card>
  )
}

// ── Roles table ───────────────────────────────────────────────────────────────
function RolesTable({ roles, allPermissions }: { roles: AdminRole[]; allPermissions: Permission[] }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  const permLabel = (name: string) => allPermissions.find((p) => p.name === name)?.label ?? name

  const del = useMutation({
    mutationFn: (roleName: string) => api.del('/admin/roles/' + encodeURIComponent(roleName)),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.roles })
      toast(res.flash || '已删除', 'success')
    },
    onError: (err) => {
      // Built-in roles cannot be deleted; the handler returns a 4xx whose flash
      // we surface here.
      if (err instanceof ApiError) toast(err.message, 'error')
      else toast('删除失败', 'error')
    },
  })

  async function onDelete(role: AdminRole) {
    const ok = await confirm({
      title: '删除角色',
      message: `确定要删除角色「${role.label || role.name}」吗？此操作不可撤销。`,
      confirmLabel: '删除',
      danger: true,
    })
    if (ok) del.mutate(role.name)
  }

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>角色名称</th>
            <th>显示名称</th>
            <th>权限</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {roles.map((r) => (
            <tr key={r.name}>
              <td>
                <code className="mono" style={{ color: 'var(--blue-d)' }}>
                  {r.name}
                </code>
              </td>
              <td>{r.label || <span style={{ color: 'var(--text2)' }}>（无）</span>}</td>
              <td style={{ fontSize: '.8rem' }}>
                {r.permissions?.length ? (
                  r.permissions.map((p) => (
                    <span key={p} className="proj-tag">
                      {permLabel(p)}
                    </span>
                  ))
                ) : (
                  <span style={{ color: 'var(--text2)' }}>（无权限）</span>
                )}
              </td>
              <td>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => onDelete(r)}
                  loading={del.isPending && del.variables === r.name}
                >
                  删除
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
