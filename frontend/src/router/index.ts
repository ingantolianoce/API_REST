import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '../stores/auth'

declare module 'vue-router' {
  interface RouteMeta {
    public?: boolean
    permission?: string
  }
}

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: () => import('../views/LoginView.vue'), meta: { public: true } },
    { path: '/mfa', component: () => import('../views/MfaView.vue'), meta: { public: true } },
    { path: '/cambiar-clave', component: () => import('../views/ChangePasswordView.vue') },
    { path: '/activar-mfa', component: () => import('../views/MfaSetupView.vue') },
    { path: '/', component: () => import('../views/HomeView.vue') },
    { path: '/usuarios', component: () => import('../views/UsersView.vue'), meta: { permission: 'user:read' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

// Guardia de navegacion = comodidad de UX. El servidor vuelve a verificar cada peticion.
router.beforeEach(async (to) => {
  const auth = useAuth()
  if (!auth.loaded) await auth.load()
  if (to.meta.public) return to.path === '/mfa' || !auth.me ? true : '/'
  if (!auth.me) return '/login'
  if (auth.me.mustChangePassword && to.path !== '/cambiar-clave') return '/cambiar-clave'
  if (to.meta.permission && !auth.can(to.meta.permission)) return '/'
  return true
})
