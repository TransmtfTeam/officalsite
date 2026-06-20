import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'

interface ConfirmOptions {
  title?: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  icon?: string
  danger?: boolean
}

type ConfirmFn = (opts: ConfirmOptions) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn | null>(null)

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [opts, setOpts] = useState<ConfirmOptions | null>(null)
  const resolver = useRef<((v: boolean) => void) | null>(null)

  const confirm = useCallback<ConfirmFn>((o) => {
    setOpts(o)
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve
    })
  }, [])

  const settle = useCallback((v: boolean) => {
    resolver.current?.(v)
    resolver.current = null
    setOpts(null)
  }, [])

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <div
        className={`cdialog-overlay${opts ? ' active' : ''}`}
        onClick={(e) => {
          if (e.target === e.currentTarget) settle(false)
        }}
      >
        {opts && (
          <div className="cdialog" role="dialog" aria-modal="true">
            <div className="cdialog-icon">{opts.icon ?? '⚠️'}</div>
            <div className="cdialog-title">{opts.title ?? '确认操作'}</div>
            <div className="cdialog-msg">{opts.message}</div>
            <div className="cdialog-actions">
              <button className="btn btn-ghost" onClick={() => settle(false)}>
                {opts.cancelLabel ?? '取消'}
              </button>
              <button
                className={`btn ${opts.danger === false ? 'btn-primary' : 'btn-danger'}`}
                autoFocus
                onClick={() => settle(true)}
              >
                {opts.confirmLabel ?? '确认'}
              </button>
            </div>
          </div>
        )}
      </div>
    </ConfirmContext.Provider>
  )
}

export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm must be used within ConfirmProvider')
  return ctx
}
