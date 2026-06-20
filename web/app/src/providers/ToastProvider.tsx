import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'

export type ToastType = 'success' | 'error' | 'info'
interface ToastItem {
  id: number
  msg: string
  type: ToastType
  leaving?: boolean
}

interface ToastApi {
  toast: (msg: string, type?: ToastType, durationMs?: number) => void
}

const ToastContext = createContext<ToastApi | null>(null)

let seq = 1

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const timers = useRef<Record<number, ReturnType<typeof setTimeout>>>({})

  const remove = useCallback((id: number) => {
    setItems((cur) => cur.map((t) => (t.id === id ? { ...t, leaving: true } : t)))
    setTimeout(() => setItems((cur) => cur.filter((t) => t.id !== id)), 280)
  }, [])

  const toast = useCallback(
    (msg: string, type: ToastType = 'success', durationMs?: number) => {
      if (!msg) return
      const id = seq++
      setItems((cur) => [...cur, { id, msg, type }])
      const ttl = typeof durationMs === 'number' ? durationMs : type === 'error' ? 4500 : 2800
      if (ttl > 0) {
        timers.current[id] = setTimeout(() => remove(id), ttl)
      }
    },
    [remove],
  )

  useEffect(() => {
    const t = timers.current
    return () => Object.values(t).forEach(clearTimeout)
  }, [])

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div id="toast-stack" aria-live="polite" aria-atomic="true">
        {items.map((t) => (
          <div key={t.id} className={`ti-toast ${t.type} in${t.leaving ? ' out' : ''}`}>
            <span className="ti-toast-icon">{t.type === 'success' ? '✓' : t.type === 'error' ? '!' : 'i'}</span>
            <span className="ti-toast-msg">{t.msg}</span>
            <button type="button" className="ti-toast-close" aria-label="关闭" onClick={() => remove(t.id)}>
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

// A module-level setter lets non-React code (the QueryClient error handler)
// reach the active toast function.
let externalToast: ToastApi['toast'] | null = null
export function bindExternalToast(fn: ToastApi['toast']) {
  externalToast = fn
}
export function fireToast(msg: string, type?: ToastType) {
  externalToast?.(msg, type)
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

// Helper component that registers the toast fn for external (non-hook) callers.
export function ToastBridge() {
  const { toast } = useToast()
  useEffect(() => {
    bindExternalToast(toast)
  }, [toast])
  return null
}
