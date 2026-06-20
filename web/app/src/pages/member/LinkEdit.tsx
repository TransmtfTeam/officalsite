import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams, Link } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Input } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'

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

export default function LinkEdit() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const { toast } = useToast()

  const { data, isLoading, isError } = useQuery({
    queryKey: qk.memberLink(id),
    queryFn: () => api.get<MemberLink>('/member/links/' + id),
    enabled: !!id,
  })

  const [form, setForm] = useState<LinkInput | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  // Hydrate the form once the link loads.
  useEffect(() => {
    if (data) {
      setForm({
        name: data.name,
        url: data.url,
        icon: data.icon,
        sortOrder: data.sortOrder,
      })
    }
  }, [data])

  function patch<K extends keyof LinkInput>(key: K, value: LinkInput[K]) {
    setForm((f) => (f ? { ...f, [key]: value } : f))
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      if (!form) throw new Error('form not ready')
      return api.patch<MemberLink>('/member/links/' + id, {
        name: form.name.trim(),
        url: form.url.trim(),
        icon: form.icon.trim(),
        sortOrder: form.sortOrder,
      })
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberLinks })
      qc.invalidateQueries({ queryKey: qk.memberLink(id) })
      toast(res.flash || '已保存', 'success')
      navigate('/member/links')
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        setFieldErrors(err.fieldErrors ?? {})
        toast(err.message, 'error')
      }
    },
  })

  // ── Icon upload ─────────────────────────────────────────────────────────────
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
      fd.set('icon_file', file)
      return api.postForm<{ iconUrl: string }>('/member/links/' + id + '/icon', fd)
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.memberLink(id) })
      qc.invalidateQueries({ queryKey: qk.memberLinks })
      toast(res.flash || '图标已上传', 'success')
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
    if (!form.name.trim()) errs.name = '请输入名称'
    if (!form.url.trim()) errs.url = '请输入链接地址'
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
        <h1 className="panel-title">编辑友情链接</h1>
        <div className="card">
          <EmptyState>加载链接失败或链接不存在</EmptyState>
        </div>
      </>
    )
  }

  const currentIcon = preview || data.icon

  return (
    <>
      <div style={{ marginBottom: '.5rem' }}>
        <Link to="/member/links" style={{ color: 'var(--text2)', fontSize: '.9rem' }}>
          ← 友情链接
        </Link>
      </div>
      <h1 className="panel-title">编辑友情链接</h1>

      <div className="form-panel">
        <form onSubmit={submit}>
          <div className="form-row">
            <Input
              label="名称"
              value={form.name}
              onChange={(e) => patch('name', e.target.value)}
              error={fieldErrors.name}
            />
            <Input
              label="链接地址"
              type="url"
              value={form.url}
              onChange={(e) => patch('url', e.target.value)}
              error={fieldErrors.url}
            />
          </div>
          <div className="form-row">
            <Input
              label="排序值（小值靠前）"
              type="number"
              value={form.sortOrder}
              onChange={(e) => patch('sortOrder', Number(e.target.value) || 0)}
            />
          </div>
          <div style={{ display: 'flex', gap: '.8rem' }}>
            <Button type="submit" loading={saveMutation.isPending}>
              保存
            </Button>
            <Link to="/member/links" className="btn btn-ghost">
              取消
            </Link>
          </div>
        </form>
      </div>

      <div className="form-panel" style={{ marginTop: '1rem' }}>
        <p className="form-panel-title">图标</p>
        <div
          style={{
            display: 'flex',
            gap: '1rem',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            marginBottom: '.8rem',
          }}
        >
          <div
            style={{
              width: 64,
              height: 64,
              borderRadius: 8,
              overflow: 'hidden',
              background: '#f3f4f6',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            {currentIcon ? (
              <img src={currentIcon} alt="图标" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            ) : (
              <span style={{ color: '#9ca3af', fontSize: '1.2rem' }}>🔗</span>
            )}
          </div>
          <form onSubmit={uploadSubmit} style={{ flex: 1, minWidth: 240 }}>
            <input className="form-control" type="file" accept="image/*" onChange={onFile} />
            <p style={{ fontSize: '.78rem', color: 'var(--text2)', margin: '.4rem 0' }}>
              支持任意图片格式，单文件不超过 5MB。
            </p>
            <Button type="submit" variant="ghost" size="sm" loading={uploadMutation.isPending} disabled={!file}>
              上传图标
            </Button>
          </form>
        </div>
      </div>
    </>
  )
}
