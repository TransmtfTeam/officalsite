import './styles/app.css'
import './styles/ui.css'
import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider, MutationCache } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { ToastProvider, ToastBridge, fireToast } from './providers/ToastProvider'
import { ConfirmProvider } from './providers/ConfirmProvider'
import { AuthProvider } from './providers/AuthProvider'
import { ErrorBoundary } from './components/ErrorBoundary'
import { ApiError } from './api/client'
import { App } from './App'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      retry: (count, err) => {
        if (err instanceof ApiError && [400, 401, 403, 404, 422].includes(err.status)) return false
        return count < 2
      },
    },
  },
  mutationCache: new MutationCache({
    onError: (err) => {
      const msg = err instanceof Error ? err.message : '操作失败'
      fireToast(msg, 'error')
    },
  }),
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <ToastBridge />
          <ConfirmProvider>
            <BrowserRouter>
              <AuthProvider>
                <App />
              </AuthProvider>
            </BrowserRouter>
          </ConfirmProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
)
