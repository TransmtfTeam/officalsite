import type { InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes, ReactNode } from 'react'

export function FormGroup({ label, error, children, hint }: { label?: ReactNode; error?: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="form-group">
      {label && <label className="form-label">{label}</label>}
      {children}
      {hint && <div style={{ fontSize: '.78rem', color: 'var(--text2)' }}>{hint}</div>}
      {error && <div className="field-error">{error}</div>}
    </div>
  )
}

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode
  error?: string
  hint?: ReactNode
}
export function Input({ label, error, hint, className, ...rest }: InputProps) {
  const field = <input className={`form-control${className ? ' ' + className : ''}`} {...rest} />
  if (label === undefined && hint === undefined && error === undefined) return field
  return (
    <FormGroup label={label} error={error} hint={hint}>
      {field}
    </FormGroup>
  )
}

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: ReactNode
  error?: string
  children: ReactNode
}
export function Select({ label, error, className, children, ...rest }: SelectProps) {
  const field = (
    <select className={`form-control${className ? ' ' + className : ''}`} {...rest}>
      {children}
    </select>
  )
  if (label === undefined && error === undefined) return field
  return (
    <FormGroup label={label} error={error}>
      {field}
    </FormGroup>
  )
}

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: ReactNode
  error?: string
}
export function Textarea({ label, error, className, ...rest }: TextareaProps) {
  const field = <textarea className={`form-control${className ? ' ' + className : ''}`} {...rest} />
  if (label === undefined && error === undefined) return field
  return (
    <FormGroup label={label} error={error}>
      {field}
    </FormGroup>
  )
}

export function Checkbox({ label, ...rest }: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer' }}>
      <input type="checkbox" {...rest} />
      <span style={{ fontSize: '.88rem' }}>{label}</span>
    </label>
  )
}
