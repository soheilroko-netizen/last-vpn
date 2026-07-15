import { defineConfig } from 'vite';
import tauri from 'vite-plugin-tauri';

export default defineConfig({
  plugins: [tauri()],
  build: {
    target: 'es2020',
    minify: 'esbuild',
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
});