import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// The Go server embeds web/app/dist and serves index.html as the SPA shell for
// every human-facing route, plus /app/assets/* (hashed, immutable) for assets.
// base:'/app/' namespaces all generated asset URLs under /app/assets/.
//
// CSP is strict (script-src 'self'): modulePreload.polyfill:false avoids the
// only inline script Vite would otherwise emit.
export default defineConfig({
  plugins: [react()],
  base: '/app/',
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2020',
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
      '/oauth2': 'http://localhost:8080',
      '/auth': 'http://localhost:8080',
      '/login/2fa': 'http://localhost:8080',
      '/login/passkey': 'http://localhost:8080',
      '/profile/passkey': 'http://localhost:8080',
      '/profile/2fa/qr': 'http://localhost:8080',
      '/uploads': 'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
      '/static': 'http://localhost:8080',
    },
  },
})
