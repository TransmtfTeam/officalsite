import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Input, Select, Textarea, Checkbox } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'

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

export default function ProjectEdit() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const { toast } = useToast()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.memberProject(id),
    queryFn: () => api.get<MemberProject>('/member/projects/' + id),
    enabled: !!id,
  })

  const [form, setForm] = useState<ProjectInput | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  // Hydrate the form once the project loads.
  useEffect(() => {
    if (data) {
      setForm({
        slug: data.slug,
        nameZh: data.nameZh,
        nameEn: data.nameEn,
        descZh: data.descZh,
        descEn: data.descEn,
        status: data.status,
        url: data.url,
        tags: data.tags,
        featured: data.featured,
        sortOrder: data.sortOrder,
      })
    }
  }, [data])

  function patch<K extends keyof ProjectInput>(key: K, value: ProjectInput[K]) {
    setForm((f) => (f ? { ...f, [key]: value } : f))
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      if (!form) throw new Error('form not ready')
      return api.patch<MemberProject>('/member/projects/' + id, {
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
      })
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberProjects })
      qc.invalidateQueries({ queryKey: qk.memberProject(id) })
      toast(res.flash || '已保存', 'success')
      navigate('/member/projects')
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        setFieldErrors(err.fieldErrors ?? {})
        toast(err.message, 'error')
      }
    },
  })

  // ── Image upload ────────────────────────────────────────────────────────────
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<string | null>(null)

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null
    setFile(f)
    setPreview(f ? URL.createObjectURL(f) : null)
  }

  const uploadMutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error('no file')
      const fd = new FormData()
      fd.set('image_file', file)
      return api.postForm<{ imageUrl: string }>('/member/projects/' + id + '/image', fd)
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberProject(id) })
      qc.invalidateQueries({ queryKey: qk.memberProjects })
      toast(res.flash || '图片已上传', 'success')
      setFile(null)
      setPreview(null)
    },
    onError: (err) => {
      if (err instanceof ApiError) toast(err.message, 'error')
    },
  })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!form) return
    const errs: Record<string, string> = {}
    if (!form.slug.trim()) errs.slug = '请输入项目代号'
    setFieldErrors(errs)
    if (Object.keys(errs).length > 0) return
    saveMutation.mutate()
  }

  function uploadSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (file) uploadMutation.mutate()
  }

  if (isLoading || (!form && !isError)) return <PageLoading />
  if (isError || !data || !form) {
    return (
      <>
        <h1 className="panel-title">编辑项目</h1>
        <div className="card">
          <EmptyState>加载项目失败或项目不存在</EmptyState>
        </div>
      </>
    )
  }

  return (
    <>
      <div style={{ marginBottom: '.5rem' }}>
        <Link to="/member/projects" style={{ color: 'var(--text2)', fontSize: '.9rem' }}>
          ← 项目管理
        </Link>
      </div>
      <h1 className="panel-title">编辑项目</h1>
      <p className="panel-sub">修改项目信息并保存。</p>

      <form className="form-panel" onSubmit={submit}>
        <div className="form-row">
          <Input
            label="项目代号"
            value={form.slug}
            onChange={(e) => patch('slug', e.target.value)}
            error={fieldErrors.slug}
          />
          <Input label="中文名" value={form.nameZh} onChange={(e) => patch('nameZh', e.target.value)} />
          <Input label="英文名" value={form.nameEn} onChange={(e) => patch('nameEn', e.target.value)} />
        </div>
        <div className="form-row">
          <Textarea label="中文简介" rows={3} value={form.descZh} onChange={(e) => patch('descZh', e.target.value)} />
          <Textarea label="英文简介" rows={3} value={form.descEn} onChange={(e) => patch('descEn', e.target.value)} />
        </div>
        <div className="form-row">
          <Select label="状态" value={form.status} onChange={(e) => patch('status', e.target.value)}>
            <option value="active">进行中</option>
            <option value="planning">规划中</option>
            <option value="completed">已完成</option>
          </Select>
          <Input label="项目链接" type="url" value={form.url} onChange={(e) => patch('url', e.target.value)} />
          <Input label="标签（数组格式）" value={form.tags} onChange={(e) => patch('tags', e.target.value)} />
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
        <div style={{ display: 'flex', gap: '.6rem' }}>
          <Button type="submit" size="sm" loading={saveMutation.isPending}>
            保存修改
          </Button>
          <Link to="/member/projects" className="btn btn-ghost btn-sm">
            返回列表
          </Link>
        </div>
      </form>

      <div className="form-panel" style={{ marginTop: '1.5rem' }}>
        <p className="form-panel-title">项目图片</p>
        {(preview || data.imageUrl) && (
          <div style={{ marginBottom: '1rem' }}>
            <img
              src={preview || data.imageUrl}
              alt="项目图片"
              style={{
                maxWidth: '100%',
                maxHeight: 240,
                borderRadius: 8,
                border: '1px solid rgba(0,0,0,0.08)',
              }}
            />
          </div>
        )}
        <form onSubmit={uploadSubmit}>
          <div className="form-group">
            <label className="form-label">上传图片（PNG/JPEG，最大5MB）</label>
            <input
              className="form-control"
              type="file"
              accept="image/png,image/jpeg"
              onChange={onFile}
            />
          </div>
          <Button type="submit" size="sm" loading={uploadMutation.isPending} disabled={!file}>
            上传图片
          </Button>
        </form>
      </div>
    </>
  )
}
