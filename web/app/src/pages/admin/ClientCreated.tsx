import { useState } from 'react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { Button } from '@/components/ui'
import { useToast } from '@/providers/ToastProvider'
import type { AdminClient } from './Clients'

interface CreatedState {
  client: AdminClient
  clientSecret: string
}

export default function ClientCreated() {
  const location = useLocation()
  const { toast } = useToast()
  const [copied, setCopied] = useState(false)

  const state = location.state as CreatedState | null

  // The plaintext secret only lives in router state; a direct visit or refresh
  // has no state, so there is nothing to show — bounce back to the list.
  if (!state?.client || !state.clientSecret) {
    return <Navigate to="/admin/clients" replace />
  }

  const { client, clientSecret } = state

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(clientSecret)
      setCopied(true)
      toast('已复制应用密钥', 'success')
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast('复制失败，请手动选择复制', 'error')
    }
  }

  return (
    <>
      <h1 className="panel-title">应用创建成功</h1>
      <p className="panel-sub">请立即保存以下凭证，应用密钥仅显示一次。</p>

      <div className="detail-section">
        <div className="detail-section-title">🎉 {client.name} 已创建</div>
        <div className="detail-row">
          <div className="detail-key">应用标识</div>
          <div className="detail-val mono">{client.clientId}</div>
        </div>
      </div>

      <div className="secret-box">
        <p style={{ fontWeight: 600, marginBottom: '.6rem' }}>
          ⚠️ 应用密钥（仅显示一次，请立即复制保存，关闭后将无法再次查看）
        </p>
        <div className="secret-val" style={{ marginBottom: '.8rem' }}>
          {clientSecret}
        </div>
        <Button size="sm" onClick={copySecret}>
          {copied ? '已复制' : '复制密钥'}
        </Button>
      </div>

      <div style={{ marginTop: '1.5rem', display: 'flex', gap: '.8rem', flexWrap: 'wrap' }}>
        <Link to={`/admin/clients/${client.id}`} className="btn btn-primary">
          查看应用详情
        </Link>
        <Link to="/admin/clients" className="btn btn-ghost">
          返回列表
        </Link>
      </div>
    </>
  )
}
