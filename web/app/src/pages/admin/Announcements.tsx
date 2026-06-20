import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'
import { qk } from '@/lib/queryKeys'
import { Button, EmptyState, PageLoading } from '@/components/ui'
import { Textarea } from '@/components/form'
import { useToast } from '@/providers/ToastProvider'

// Each manageable client paired with its current announcement content.
interface AnnouncementItem {
  id: string
  clientId: string
  name: string
  announcement: string
}

export default function Announcements() {
  const { data, isLoading, isError } = useQuery({
    queryKey: qk.announcements,
    queryFn: () => api.get<AnnouncementItem[]>('/admin/announcements'),
  })

  if (isLoading && !data) return <PageLoading />

  const items = data ?? []

  return (
    <>
      <h1 className="panel-title">应用公告</h1>
      <p className="panel-sub">为各应用设置展示给用户的公告内容，留空表示不展示。</p>

      {isError ? (
        <div className="card">
          <EmptyState>加载公告列表失败，请稍后重试</EmptyState>
        </div>
      ) : items.length === 0 ? (
        <div className="card">
          <EmptyState>暂无可管理的应用</EmptyState>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {items.map((item) => (
            <AnnouncementCard key={item.clientId} item={item} />
          ))}
        </div>
      )}
    </>
  )
}

function AnnouncementCard({ item }: { item: AnnouncementItem }) {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [content, setContent] = useState(item.announcement)

  // Re-sync the local draft when the server value changes (e.g. after refetch).
  useEffect(() => {
    setContent(item.announcement)
  }, [item.announcement])

  const save = useMutation({
    mutationFn: () =>
      api.post('/admin/announcements/' + encodeURIComponent(item.clientId), { content }),
    onSuccess: (res) => {
      toast(res.flash || '公告已保存', 'success')
      qc.invalidateQueries({ queryKey: qk.announcements })
    },
    onError: (err) => {
      toast(err instanceof ApiError ? err.message : '保存失败', 'error')
    },
  })

  const dirty = content !== item.announcement

  return (
    <div className="card">
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          gap: '1rem',
          marginBottom: '.75rem',
          flexWrap: 'wrap',
        }}
      >
        <h2 className="form-panel-title" style={{ margin: 0 }}>
          {item.name}
        </h2>
        <span className="mono" style={{ color: 'var(--text2)' }}>
          {item.clientId}
        </span>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          save.mutate()
        }}
      >
        <Textarea
          rows={4}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="输入公告内容…"
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '.75rem' }}>
          <Button type="submit" size="sm" loading={save.isPending} disabled={!dirty}>
            保存
          </Button>
        </div>
      </form>
    </div>
  )
}
