import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'charts': ['recharts'],
          'three-core': ['three'],
          'three-react': ['@react-three/fiber', '@react-three/drei'],
        },
      },
    },
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: Number(process.env.VITE_DEV_PORT) || 8081,
    strictPort: true,
    host: '127.0.0.1',
    ...(process.env.VITE_HMR_CLIENT_PORT
      ? { hmr: { clientPort: Number(process.env.VITE_HMR_CLIENT_PORT) } }
      : {}),
    proxy: {
      '/api': {
        target: `http://localhost:${process.env.VITE_BACKEND_PORT || 8000}`,
        changeOrigin: true,
      },
      '^/g/': {
        target: `http://localhost:${process.env.VITE_BACKEND_PORT || 8000}`,
        changeOrigin: true,
      },
    }
  }
})
