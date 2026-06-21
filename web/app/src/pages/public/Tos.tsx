import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'

export default function Tos() {
  const { data } = useQuery({ queryKey: qk.tos, queryFn: () => api.get<{ content: string }>('/tos') })
  return (
    <div className="legal-page">
      <h1 style={{ marginBottom: '1rem' }}>服务条款</h1>
      <div className="card">
        {data?.content ? (
          <div className="ti-modal-b" dangerouslySetInnerHTML={{ __html: data.content }} />
        ) : (
          <p style={{ color: 'var(--text2)' }}>暂无服务条款内容。</p>
        )}
      </div>
    </div>
  )
}
