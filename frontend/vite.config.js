import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['@noble/post-quantum'],
  },
  build: {
    target: 'esnext',
  },
});
