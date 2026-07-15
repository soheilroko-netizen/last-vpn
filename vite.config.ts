import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    target: 'es2020',
    minify: 'esbuild',
  },
  clearScreen: false,
  server: {
    host: true,
    port: 1420,
    strictPort: true,
  },
});