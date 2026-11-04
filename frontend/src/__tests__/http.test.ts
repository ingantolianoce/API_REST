import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, messageFor, readCookie } from '../api/http'

function res(status: number, body?: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers })
}

describe('http client', () => {
  beforeEach(() => {
    document.cookie = 'XSRF-TOKEN=tok123; path=/'
  })
  afterEach(() => {
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    vi.restoreAllMocks()
  })

  it('lee cookies por nombre exacto', () => {
    expect(readCookie('XSRF-TOKEN')).toBe('tok123')
    expect(readCookie('XSRF')).toBeUndefined()
  })

  it('envia el token CSRF en peticiones que cambian estado', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockResolvedValue(res(204))
    await api('/api/v1/auth/logout', { method: 'POST' })
    const init = f.mock.calls[0][1] as RequestInit
    expect((init.headers as Record<string, string>)['X-XSRF-TOKEN']).toBe('tok123')
    expect(init.credentials).toBe('same-origin')
  })

  it('no envia CSRF en GET y nunca usa Authorization ni almacenamiento local', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockResolvedValue(res(200, { ok: true }))
    await api('/api/v1/auth/me')
    const headers = (f.mock.calls[0][1] as RequestInit).headers as Record<string, string>
    expect(headers['X-XSRF-TOKEN']).toBeUndefined()
    expect(headers['Authorization']).toBeUndefined()
    expect(localStorage.length).toBe(0)
  })

  it('convierte errores en ApiError con codigo y Retry-After', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(res(429, { code: 'RATE_LIMITED', requestId: 'r-1' }, { 'Retry-After': '30' }))
    const err = (await api('/api/v1/auth/login', { method: 'POST', body: {} }).catch((e: unknown) => e)) as ApiError
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(429)
    expect(err.retryAfter).toBe(30)
  })

  it('los mensajes al usuario son genericos y explican el rechazo de contrasenas', () => {
    expect(messageFor(new ApiError(401, 'INVALID_CREDENTIALS'))).toBe('Credenciales inválidas.')
    expect(messageFor(new ApiError(422, 'PASSWORD_REJECTED', ['PASSWORD_BREACHED']))).toContain('filtraciones')
    expect(messageFor(new ApiError(500, 'INTERNAL_ERROR', [], 'abc-123'))).toContain('abc-123')
    expect(messageFor(new Error('x'))).toBe('No se pudo conectar con el servidor.')
  })
})
