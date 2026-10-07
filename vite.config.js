import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 1420,
    strictPort: true,
    host: '127.0.0.1', 
    watch: {
      ignored: ["**/src-tauri/target/**"],
    },
  },
  build: {
    outDir: 'dist'
  }
});