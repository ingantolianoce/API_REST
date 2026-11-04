import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuth } from '../stores/auth'

describe('auth store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('can() es falso sin sesion y respeta los permisos recibidos del servidor', () => {
    const auth = useAuth()
    expect(auth.can('user:read')).toBe(false)
    auth.me = { id: '1', email: 'a@b.c', fullName: 'A', roles: ['gestor'], permissions: ['user:read'], mfaEnabled: true, mustChangePassword: false }
    expect(auth.can('user:read')).toBe(true)
    expect(auth.can('user:create')).toBe(false)
  })
})
