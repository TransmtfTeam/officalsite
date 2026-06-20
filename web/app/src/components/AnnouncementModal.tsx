import { useEffect, useState } from 'react'
import { useAuth } from '@/providers/AuthProvider'
import { DocModal } from './DocModal'

// Shows the site announcement once per revision (keyed by annHash in
// localStorage), mirroring the old showAnn() behavior.
export function AnnouncementModal() {
  const { settings } = useAuth()
  const [open, setOpen] = useState(false)

  const annHash = settings?.annHash ?? ''
  const annZH = settings?.annZH ?? ''
  const annEN = settings?.annEN ?? ''
  const hasAnn = !!(annZH || annEN)

  useEffect(() => {
    if (!hasAnn || !annHash) return
    try {
      if (localStorage.getItem('ann-dismiss:' + annHash) === '1') return
    } catch {
      /* ignore */
    }
    setOpen(true)
  }, [hasAnn, annHash])

  if (!hasAnn) return null

  const html =
    `<div class="ti-ann-badge">📢 站点公告</div>` +
    (annZH ? `<div>${annZH}</div>` : '') +
    (annEN ? `<div style="margin-top:.8rem;color:#64748b;font-size:.9rem">${annEN}</div>` : '')

  const close = () => {
    try {
      localStorage.setItem('ann-dismiss:' + annHash, '1')
    } catch {
      /* ignore */
    }
    setOpen(false)
  }

  return <DocModal open={open} title={`来自 ${settings?.siteName ?? '站点'}`} html={html} okText="我知道了" onClose={close} />
}
