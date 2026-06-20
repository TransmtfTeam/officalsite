import { useEffect, useRef, type ReactNode } from 'react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title?: ReactNode
  children: ReactNode
  footer?: ReactNode
  maxWidth?: number
}

// Generic modal mirroring app.css .modal/.modal-box, with focus trap, ESC,
// backdrop-click close, body scroll lock and aria-modal.
export function Modal({ open, onClose, title, children, footer, maxWidth = 520 }: ModalProps) {
  const boxRef = useRef<HTMLDivElement>(null)
  const prevFocus = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (!open) return
    prevFocus.current = document.activeElement as HTMLElement
    document.body.style.overflow = 'hidden'
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'Tab' && boxRef.current) {
        const focusables = boxRef.current.querySelectorAll<HTMLElement>(
          'a[href],button:not([disabled]),textarea,input,select,[tabindex]:not([tabindex="-1"])',
        )
        if (focusables.length === 0) return
        const first = focusables[0]
        const last = focusables[focusables.length - 1]
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey)
    const t = setTimeout(() => {
      boxRef.current?.querySelector<HTMLElement>('input,select,textarea,button')?.focus()
    }, 30)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
      clearTimeout(t)
      prevFocus.current?.focus?.()
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <div
      className="modal open"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="modal-box" ref={boxRef} role="dialog" aria-modal="true" style={{ maxWidth }}>
        <div className="modal-close" onClick={onClose} role="button" aria-label="关闭">
          ×
        </div>
        {title && <h3 style={{ margin: '0 0 .8rem' }}>{title}</h3>}
        {children}
        {footer && (
          <div style={{ display: 'flex', gap: '.6rem', justifyContent: 'flex-end', marginTop: '1rem' }}>{footer}</div>
        )}
      </div>
    </div>
  )
}
