import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { api, ApiError } from '@/api/client'
import { AuthCard } from '@/layouts/AuthLayout'
import { Button, PageLoading } from '@/components/ui'

interface ConsentInfo {
  action: 'consent' | 'redirect'
  location?: string
  client?: { name: string; description: string; clientId: string }
  scopes?: { key: string; label: string }[]
  request?: Record<string, string>
}

export default function Consent() {
  const loc = useLocation()
  const [info, setInfo] = useState<ConsentInfo | null>(null)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    let cancelled = false
    api
      .get<ConsentInfo>('/oauth2/authorize' + loc.search)
      .then((data) => {
        if (cancelled) return
        if (data.action === 'redirect' && data.location) {
          window.location.assign(data.location)
          return
        }
        setInfo(data)
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : '授权请求无效'))
    return () => {
      cancelled = true
    }
  }, [loc.search])

  const decide = async (action: 'allow' | 'deny') => {
    if (!info?.request) return
    setSubmitting(true)
    setError('')
    try {
      const { data } = await api.post<{ location: string }>('/oauth2/authorize', { action, ...info.request })
      window.location.assign(data.location)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : '授权失败')
      setSubmitting(false)
    }
  }

  if (error) {
    return (
      <AuthCard title="授权请求">
        <div className="flash flash-err">{error}</div>
        <Button variant="ghost" onClick={() => window.location.assign('/')} style={{ width: '100%', justifyContent: 'center' }}>
          返回首页
        </Button>
      </AuthCard>
    )
  }
  if (!info || info.action !== 'consent') return <PageLoading />

  return (
    <AuthCard title="授权确认">
      <p style={{ fontSize: '.95rem' }}>
        <span className="consent-client" style={{ fontWeight: 700 }}>
          {info.client?.name}
        </span>{' '}
        请求访问您的账号，将获得以下权限：
      </p>
      {info.client?.description && <p style={{ color: 'var(--text2)', fontSize: '.85rem' }}>{info.client.description}</p>}
      <ul className="scope-list" style={{ listStyle: 'none', padding: 0, margin: '1rem 0' }}>
        {info.scopes?.map((s) => (
          <li key={s.key} style={{ display: 'flex', gap: '.5rem', alignItems: 'center', padding: '.35rem 0' }}>
            <span style={{ color: '#16a34a', fontWeight: 700 }}>✓</span>
            {s.label}
          </li>
        ))}
      </ul>
      <div style={{ display: 'flex', gap: '.6rem' }}>
        <Button variant="ghost" onClick={() => decide('deny')} disabled={submitting} style={{ flex: 1, justifyContent: 'center' }}>
          拒绝
        </Button>
        <Button onClick={() => decide('allow')} loading={submitting} style={{ flex: 1, justifyContent: 'center' }}>
          允许
        </Button>
      </div>
    </AuthCard>
  )
}
