import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In dev the UI runs on 5173 and talks to the backend in the container on 9080.
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:9080', changeOrigin: true },
      '/ws': { target: 'ws://localhost:9080', ws: true },
    },
  },
  build: { outDir: 'dist', chunkSizeWarningLimit: 1200 },
})
