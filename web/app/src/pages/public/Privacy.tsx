import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { qk } from '@/lib/queryKeys'

export default function Privacy() {
  const { data } = useQuery({ queryKey: qk.privacy, queryFn: () => api.get<{ content: string }>('/privacy') })
  return (
    <div style={{ maxWidth: 820, margin: '0 auto', padding: '90px 1.2rem 3rem' }}>
      <h1 style={{ marginBottom: '1rem' }}>隐私政策</h1>
      <div className="card">
        {data?.content ? (
          <div className="ti-modal-b" dangerouslySetInnerHTML={{ __html: data.content }} />
        ) : (
          <p style={{ color: 'var(--text2)' }}>暂无隐私政策内容。</p>
        )}
      </div>
    </div>
  )
}
