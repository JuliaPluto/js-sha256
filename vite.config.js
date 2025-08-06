import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/sha256.mjs'),
      name: 'sha256',
      fileName: (format) => `sha256.${format === 'es' ? 'mjs' : 'min.js'}`,
      formats: ['es', 'umd']
    },
    rollupOptions: {
      external: [],
      output: {
        globals: {},
        exports: 'named'
      }
    },
    outDir: 'build',
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: false,
        drop_debugger: true
      },
      format: {
        comments: /^\**!|@preserve|@license|@cc_on/i
      }
    }
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.js']
  }
});