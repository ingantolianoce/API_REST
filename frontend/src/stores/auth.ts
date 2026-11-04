import { defineStore } from 'pinia'
import { api, ensureCsrf } from '../api/http'

export interface Me {
  id: string
  email: string
  fullName: string
  roles: string[]
  permissions: string[]
  mfaEnabled: boolean
  mustChangePassword: boolean
}
interface LoginResponse {
  status: 'OK' | 'MFA_REQUIRED'
  mustChangePassword: boolean
  mfaEnrollmentRequired: boolean
}

export const useAuth = defineStore('auth', {
  state: () => ({ me: null as Me | null, loaded: false }),
  actions: {
    /** SOLO para ocultar opciones en la interfaz. La autorizacion real la hace SIEMPRE el servidor. */
    can(permission: string): boolean {
      return this.me?.permissions.includes(permission) ?? false
    },
    async load(): Promise<void> {
      try {
        this.me = await api<Me>('/api/v1/auth/me')
      } catch {
        this.me = null
      }
      this.loaded = true
    },
    async login(email: string, password: string): Promise<LoginResponse> {
      await ensureCsrf()
      const r = await api<LoginResponse>('/api/v1/auth/login', { method: 'POST', body: { email, password } })
      if (r.status === 'OK') await this.load()
      return r
    },
    async verifyMfa(code: string): Promise<void> {
      await api('/api/v1/auth/mfa/verify', { method: 'POST', body: { code } })
      await this.load()
    },
    async logout(): Promise<void> {
      try {
        await api('/api/v1/auth/logout', { method: 'POST' })
      } finally {
        this.me = null
      }
    },
  },
})
