import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Input } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'

interface MemberLink {
  id: string
  name: string
  url: string
  icon: string
  sortOrder: number
  createdAt: string
}

interface LinkInput {
  name: string
  url: string
  icon: string
  sortOrder: number
}

const EMPTY_FORM: LinkInput = { name: '', url: '', icon: '', sortOrder: 0 }

export default function Links() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.memberLinks,
    queryFn: () => api.get<MemberLink[]>('/member/links'),
  })

  const [form, setForm] = useState<LinkInput>(EMPTY_FORM)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  function patch<K extends keyof LinkInput>(key: K, value: LinkInput[K]) {
    setForm((f) => ({ ...f, [key]: value }))
  }

  const createMutation = useMutation({
    mutationFn: () =>
      api.post<MemberLink>('/member/links', {
        name: form.name.trim(),
        url: form.url.trim(),
        icon: form.icon.trim(),
        sortOrder: form.sortOrder,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberLinks })
      toast(res.flash || '链接已创建', 'success')
      setForm(EMPTY_FORM)
      setFieldErrors({})
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        setFieldErrors(err.fieldErrors ?? {})
        toast(err.message, 'error')
      }
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.del('/member/links/' + id),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberLinks })
      toast(res.flash || '链接已删除', 'success')
    },
    onError: (err) => {
      if (err instanceof ApiError) toast(err.message, 'error')
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (!form.name.trim()) errs.name = '请输入名称'
    if (!form.url.trim()) errs.url = '请输入链接地址'
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    createMutation.mutate()
  }

  async function onDelete(l: MemberLink) {
    const ok = await confirm({
      title: '删除链接',
      message: '确认删除该链接吗？此操作不可撤销。',
      icon: '🗑️',
      danger: true,
    })
    if (ok) deleteMutation.mutate(l.id)
  }

  if (isLoading) return <PageLoading />

  const links = data ?? []

  return (
    <>
      <h1 className="panel-title">友情链接管理</h1>
      <p className="panel-sub">添加在首页底部展示的友情链接，支持图标。</p>

      <div className="form-panel">
        <p className="form-panel-title">新增链接</p>
        <form onSubmit={submit}>
          <div className="form-row">
            <Input
              label="名称"
              value={form.name}
              onChange={(e) => patch('name', e.target.value)}
              error={fieldErrors.name}
              placeholder="示例链接"
            />
            <Input
              label="链接地址"
              type="url"
              value={form.url}
              onChange={(e) => patch('url', e.target.value)}
              error={fieldErrors.url}
              placeholder="请输入链接地址"
            />
          </div>
          <div className="form-row">
            <Input
              label="图标地址（可选，如网站图标）"
              type="url"
              value={form.icon}
              onChange={(e) => patch('icon', e.target.value)}
              placeholder="请输入图标地址"
            />
            <Input
              label="排序值（小值靠前）"
              type="number"
              value={form.sortOrder}
              onChange={(e) => patch('sortOrder', Number(e.target.value) || 0)}
            />
          </div>
          <Button type="submit" size="sm" loading={createMutation.isPending}>
            添加链接
          </Button>
        </form>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载友情链接失败，请稍后重试</EmptyState>
        ) : links.length === 0 ? (
          <EmptyState>暂无友情链接</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>链接</th>
                  <th>排序</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {links.map((l) => (
                  <tr key={l.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem' }}>
                        {l.icon && (
                          <img src={l.icon} alt="" style={{ width: 16, height: 16, objectFit: 'contain' }} />
                        )}
                        <strong>{l.name}</strong>
                      </div>
                    </td>
                    <td>
                      <a
                        href={l.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ fontSize: '.85rem', wordBreak: 'break-all' }}
                      >
                        {l.url}
                      </a>
                    </td>
                    <td style={{ fontSize: '.85rem' }}>{l.sortOrder}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'inline-flex', gap: '.4rem', flexWrap: 'wrap' }}>
                        <Link to={`/member/links/${l.id}/edit`} className="btn btn-ghost btn-sm">
                          编辑
                        </Link>
                        <Button variant="danger" size="sm" onClick={() => onDelete(l)}>
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
