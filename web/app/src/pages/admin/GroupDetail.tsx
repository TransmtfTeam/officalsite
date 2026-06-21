import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading, RoleBadge } from '@/components/ui'
import { Select } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'
import type { User } from '@/api/types'

interface Group {
  id: string
  name: string
  label: string
  createdAt: string
}

interface GroupDetailResponse {
  group: Group
  members: User[]
  users: User[]
}

export default function GroupDetail() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()
  const navigate = useNavigate()

  const [userId, setUserId] = useState('')

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.group(id),
    queryFn: () => api.get<GroupDetailResponse>('/admin/groups/' + id),
    enabled: !!id,
  })

  const onError = (err: unknown) =>
    toast(err instanceof ApiError ? err.message : '操作失败', 'error')

  const refresh = (flash?: string, fallback?: string) => {
    toast(flash || fallback || '操作成功', 'success')
    qc.invalidateQueries({ queryKey: qk.group(id) })
  }

  const addMember = useMutation({
    mutationFn: () => api.post('/admin/groups/' + id + '/members', { userId }),
    onSuccess: (res) => {
      setUserId('')
      refresh(res.flash, '成员已添加')
    },
    onError,
  })

  const removeMember = useMutation({
    mutationFn: (uid: string) => api.del('/admin/groups/' + id + '/members/' + uid),
    onSuccess: (res) => refresh(res.flash, '成员已移除'),
    onError,
  })

  const deleteGroup = useMutation({
    mutationFn: () => api.del('/admin/groups/' + id),
    onSuccess: (res) => {
      toast(res.flash || '分组已删除', 'success')
      qc.invalidateQueries({ queryKey: qk.groups })
      navigate('/admin/groups')
    },
    onError,
  })

  async function askDelete() {
    if (!data) return
    const ok = await confirm({
      title: '删除分组',
      message: `确定要删除分组「${data.group.label || data.group.name}」吗？此操作不可撤销。`,
      confirmLabel: '删除',
      danger: true,
    })
    if (ok) deleteGroup.mutate()
  }

  if (isLoading && !data) return <PageLoading />

  if (isError || !data) {
    return (
      <>
        <h1 className="panel-title">分组详情</h1>
        <div className="card">
          <EmptyState>加载分组详情失败，或分组不存在</EmptyState>
        </div>
        <Link to="/admin/groups" className="btn btn-ghost btn-sm">
          ← 返回分组列表
        </Link>
      </>
    )
  }

  const { group, members, users } = data
  const memberIds = new Set(members.map((m) => m.id))
  const available = users.filter((u) => !memberIds.has(u.id))

  return (
    <>
      <div style={{ marginBottom: '.5rem' }}>
        <Link to="/admin/groups" className="btn btn-ghost btn-sm">
          ← 返回分组列表
        </Link>
      </div>

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
          <h1 className="panel-title">{group.label || group.name}</h1>
          <p className="panel-sub">
            <span className="mono">{group.name}</span> · 共 {members.length} 名成员
          </p>
        </div>
        <Button variant="danger" onClick={askDelete} loading={deleteGroup.isPending}>
          删除分组
        </Button>
      </div>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <h2 className="form-panel-title">添加成员</h2>
        <form
          className="inline-fields"
          onSubmit={(e) => {
            e.preventDefault()
            if (userId) addMember.mutate()
          }}
        >
          <div className="field-grow">
            <Select label="选择用户" value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">选择用户…</option>
              {available.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.displayName ? `${u.displayName}（${u.email}）` : u.email}
                </option>
              ))}
            </Select>
          </div>
          <Button type="submit" loading={addMember.isPending} disabled={!userId}>
            添加
          </Button>
        </form>
        {available.length === 0 && (
          <p style={{ color: 'var(--text2)', margin: '.5rem 0 0', fontSize: '.85rem' }}>
            所有用户均已加入此分组。
          </p>
        )}
      </div>

      <div className="card" style={{ padding: 0 }}>
        {members.length === 0 ? (
          <EmptyState>此分组暂无成员</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>邮箱</th>
                  <th>名称</th>
                  <th>角色</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id}>
                    <td>{m.email}</td>
                    <td>{m.displayName || '—'}</td>
                    <td>
                      <RoleBadge role={m.role} />
                    </td>
                    <td>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => removeMember.mutate(m.id)}
                        disabled={removeMember.isPending}
                      >
                        移除
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
