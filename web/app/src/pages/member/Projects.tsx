import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Input, Select, Textarea, Checkbox } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'
import { useConfirm } from '@/providers/ConfirmProvider'

interface MemberProject {
  id: string
  slug: string
  nameZh: string
  nameEn: string
  descZh: string
  descEn: string
  status: string
  url: string
  tags: string
  featured: boolean
  sortOrder: number
  imageUrl: string
  createdAt: string
  updatedAt: string
}

interface ProjectInput {
  slug: string
  nameZh: string
  nameEn: string
  descZh: string
  descEn: string
  status: string
  url: string
  tags: string
  featured: boolean
  sortOrder: number
}

const STATUS_LABELS: Record<string, string> = {
  active: '进行中',
  planning: '规划中',
  completed: '已完成',
}

const EMPTY_FORM: ProjectInput = {
  slug: '',
  nameZh: '',
  nameEn: '',
  descZh: '',
  descEn: '',
  status: 'active',
  url: '',
  tags: '',
  featured: false,
  sortOrder: 0,
}

export default function Projects() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.memberProjects,
    queryFn: () => api.get<MemberProject[]>('/member/projects'),
  })

  const [form, setForm] = useState<ProjectInput>(EMPTY_FORM)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  function patch<K extends keyof ProjectInput>(key: K, value: ProjectInput[K]) {
    setForm((f) => ({ ...f, [key]: value }))
  }

  const createMutation = useMutation({
    mutationFn: () =>
      api.post<MemberProject>('/member/projects', {
        slug: form.slug.trim(),
        nameZh: form.nameZh.trim(),
        nameEn: form.nameEn.trim(),
        descZh: form.descZh,
        descEn: form.descEn,
        status: form.status,
        url: form.url.trim(),
        tags: form.tags,
        featured: form.featured,
        sortOrder: form.sortOrder,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberProjects })
      toast(res.flash || '项目已创建', 'success')
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
    mutationFn: (id: string) => api.del('/member/projects/' + id),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberProjects })
      toast(res.flash || '项目已删除', 'success')
    },
    onError: (err) => {
      if (err instanceof ApiError) toast(err.message, 'error')
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const errs: Record<string, string> = {}
    if (!form.slug.trim()) errs.slug = '请输入项目代号'
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    createMutation.mutate()
  }

  async function onDelete(p: MemberProject) {
    const ok = await confirm({
      title: '删除项目',
      message: '确认删除此项目吗？此操作不可撤销。',
      icon: '🗑️',
      danger: true,
    })
    if (ok) deleteMutation.mutate(p.id)
  }

  if (isLoading) return <PageLoading />

  const projects = data ?? []

  return (
    <>
      <h1 className="panel-title">项目管理</h1>
      <p className="panel-sub">创建和维护首页展示的团队项目。</p>

      <div className="form-panel">
        <p className="form-panel-title">新增项目</p>
        <form onSubmit={submit}>
          <div className="form-row">
            <Input
              label="项目代号"
              value={form.slug}
              onChange={(e) => patch('slug', e.target.value)}
              error={fieldErrors.slug}
              placeholder="请输入项目代号"
            />
            <Input label="中文名" value={form.nameZh} onChange={(e) => patch('nameZh', e.target.value)} />
            <Input label="英文名" value={form.nameEn} onChange={(e) => patch('nameEn', e.target.value)} />
          </div>
          <div className="form-row">
            <Textarea label="中文简介" rows={2} value={form.descZh} onChange={(e) => patch('descZh', e.target.value)} />
            <Textarea label="英文简介" rows={2} value={form.descEn} onChange={(e) => patch('descEn', e.target.value)} />
          </div>
          <div className="form-row">
            <Select label="状态" value={form.status} onChange={(e) => patch('status', e.target.value)}>
              <option value="active">进行中</option>
              <option value="planning">规划中</option>
              <option value="completed">已完成</option>
            </Select>
            <Input
              label="项目链接（可选）"
              type="url"
              value={form.url}
              onChange={(e) => patch('url', e.target.value)}
              placeholder="请输入项目链接地址"
            />
            <Input
              label="标签（数组格式）"
              value={form.tags}
              onChange={(e) => patch('tags', e.target.value)}
              placeholder='["示例标签"]'
            />
          </div>
          <div className="form-row">
            <Input
              label="排序值"
              type="number"
              value={form.sortOrder}
              onChange={(e) => patch('sortOrder', Number(e.target.value) || 0)}
            />
            <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end' }}>
              <Checkbox
                label="是否置顶"
                checked={form.featured}
                onChange={(e) => patch('featured', e.target.checked)}
              />
            </div>
          </div>
          <Button type="submit" size="sm" loading={createMutation.isPending}>
            创建项目
          </Button>
        </form>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {isError ? (
          <EmptyState>加载项目列表失败，请稍后重试</EmptyState>
        ) : projects.length === 0 ? (
          <EmptyState>暂无项目</EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>项目</th>
                  <th>状态</th>
                  <th>置顶</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {projects.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <strong>{p.nameZh || p.nameEn || p.slug}</strong>
                      {p.url && (
                        <>
                          <br />
                          <a href={p.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: '.8rem' }}>
                            {p.url}
                          </a>
                        </>
                      )}
                    </td>
                    <td>
                      <span className={`proj-status proj-status-${p.status}`}>
                        {STATUS_LABELS[p.status] ?? p.status}
                      </span>
                    </td>
                    <td>{p.featured ? '是' : '否'}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'inline-flex', gap: '.4rem', flexWrap: 'wrap' }}>
                        <Link to={`/member/projects/${p.id}/edit`} className="btn btn-ghost btn-sm">
                          编辑
                        </Link>
                        <Button variant="danger" size="sm" onClick={() => onDelete(p)}>
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
