import { useEffect } from 'react'

interface Props {
  open: boolean
  title: string
  html: string
  loading?: boolean
  okText?: string
  onClose: () => void
}

// Document preview modal (ToS / Privacy / announcements) using the ported
// .ti-modal styles. Content is trusted HTML from the server settings.
export function DocModal({ open, title, html, loading, okText = '我已阅读', onClose }: Props) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null
  return (
    <div
      className="ti-modal-ov in"
      role="dialog"
      aria-modal="true"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="ti-modal" role="document">
        <div className="ti-modal-h">
          <h3 className="ti-modal-t">{title}</h3>
          <button type="button" className="ti-modal-x" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        {loading ? (
          <div className="ti-modal-b">
            <p style={{ color: '#888' }}>加载中…</p>
          </div>
        ) : (
          <div className="ti-modal-b" dangerouslySetInnerHTML={{ __html: html || '<p style="color:#888">暂无内容</p>' }} />
        )}
        <div className="ti-modal-f">
          <button type="button" className="btn btn-primary" onClick={onClose}>
            {okText}
          </button>
        </div>
      </div>
    </div>
  )
}
