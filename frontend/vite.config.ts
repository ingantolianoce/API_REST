import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

// En desarrollo, /api se reenvia al backend: el navegador ve UN solo origen, asi la cookie de sesion
// (__Host-, SameSite=Lax) y el CSRF funcionan sin habilitar CORS.
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: { '/api': { target: process.env.BACKEND_URL ?? 'http://localhost:8080', changeOrigin: false } },
  },
  build: { sourcemap: false },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts'] },
})
