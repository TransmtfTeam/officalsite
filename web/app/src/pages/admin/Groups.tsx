import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Input } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'

interface Group {
  id: string
  name: string
  label: string
  createdAt: string
}

export default function Groups() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.groups,
    queryFn: () => api.get<Group[]>('/admin/groups'),
  })

  const [name, setName] = useState('')
  const [label, setLabel] = useState('')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  const create = useMutation({
    mutationFn: () =>
      api.post<Group>('/admin/groups', { name: name.trim(), label: label.trim() }),
    onSuccess: (res) => {
      toast(res.flash || '分组已创建', 'success')
      setName('')
      setLabel('')
      setFieldErrors({})
      qc.invalidateQueries({ queryKey: qk.groups })
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

  const del = useMutation({
    mutationFn: (id: string) => api.del('/admin/groups/' + id),
    onSuccess: (res) => {
      toast(res.flash || '分组已删除', 'success')
      qc.invalidateQueries({ queryKey: qk.groups })
    },
    onError: (err) => {
      toast(err instanceof ApiError ? err.message : '删除失败', 'error')
    },
  })

  async function askDelete(g: Group) {
    const ok = await confirm({
      title: '删除分组',
      message: `确定要删除分组「${g.label || g.name}」吗？此操作不可撤销。`,
      confirmLabel: '删除',
      danger: true,
    })
    if (ok) del.mutate(g.id)
  }

  function submitCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) {
      setFieldErrors({ name: '请输入分组名称' })
      return
    }
    create.mutate()
  }

  if (isLoading && !data) return <PageLoading />

  const groups = data ?? []

  return (
    <>
      <h1 className="panel-title">分组管理</h1>
      <p className="panel-sub">分组用于批量管理用户的应用访问权限。</p>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <h2 className="form-panel-title">新建分组</h2>
        <form onSubmit={submitCreate} className="inline-fields">
          <div className="field-grow">
            <Input
              label="名称"
              value={name}
              onChange={(e) => setName(e.target.value)}
              error={fieldErrors.name}
              hint="小写字母、数字，唯一标识"
              placeholder="例如 developers"
            />
          </div>
          <div className="field-grow">
            <Input
              label="显示名称"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="例如 开发组"
            />
          </div>
          <Button type="submit" loading={create.isPending}>
            创建分组
          </Button>
        </form>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载分组列表失败，请稍后重试</EmptyState>
        ) : groups.length === 0 ? (
          <EmptyState>暂无分组</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>显示名称</th>
                  <th>创建时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.id}>
                    <td>
                      <Link to={`/admin/groups/${g.id}`}>{g.name}</Link>
                    </td>
                    <td>{g.label || '—'}</td>
                    <td>{new Date(g.createdAt).toLocaleString()}</td>
                    <td>
                      <div style={{ display: 'inline-flex', gap: '.4rem', flexWrap: 'wrap' }}>
                        <Link to={`/admin/groups/${g.id}`} className="btn btn-ghost btn-sm">
                          管理成员
                        </Link>
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => askDelete(g)}
                          disabled={del.isPending}
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
        )}
      </div>
    </>
  )
}
