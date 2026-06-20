import { Component, type ReactNode } from 'react'

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error) {
    // eslint-disable-next-line no-console
    console.error('UI error:', error)
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ maxWidth: 560, margin: '4rem auto', padding: '0 1rem' }}>
          <div className="card">
            <h2 style={{ marginTop: 0 }}>页面出错了</h2>
            <div className="flash flash-err">{this.state.error.message || '发生未知错误'}</div>
            <button className="btn btn-primary" onClick={() => window.location.assign('/')}>
              返回首页
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
