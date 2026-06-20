import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    emptyOutDir: false,
  },
  server: {
    proxy: {
      '/api': {
        target: process.env.VITE_QUIVER_API_PROXY_TARGET ?? 'http://localhost:8236',
        changeOrigin: true,
      },
      '/health': {
        target: process.env.VITE_QUIVER_API_PROXY_TARGET ?? 'http://localhost:8236',
        changeOrigin: true,
      },
      '/metrics': {
        target: process.env.VITE_QUIVER_API_PROXY_TARGET ?? 'http://localhost:8236',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
  },
})
