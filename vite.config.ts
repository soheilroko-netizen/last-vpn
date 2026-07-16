import { defineConfig } from 'vite'

export default defineConfig({
  clearScreen: false,
  server: {
    host: true,
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
  },
})
