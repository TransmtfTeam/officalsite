import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <div style={{ maxWidth: 520, margin: '6rem auto', padding: '0 1rem', textAlign: 'center' }}>
      <h1 style={{ fontSize: 'clamp(2rem, 8vw, 3rem)', margin: 0, color: 'var(--blue-d)' }}>404</h1>
      <p style={{ color: 'var(--text2)' }}>页面不存在或已被移动。</p>
      <Link className="btn btn-primary" to="/">
        返回首页
      </Link>
    </div>
  )
}
