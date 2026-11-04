/**
 * Cliente HTTP. Reglas de seguridad:
 *  - La sesion vive en una cookie HttpOnly: JAMAS se guardan tokens en localStorage/sessionStorage.
 *  - Toda peticion que cambia estado envia el token CSRF (cookie XSRF-TOKEN -> cabecera X-XSRF-TOKEN).
 *  - Los errores del servidor son genericos (codigo + requestId); no se muestran detalles tecnicos al usuario.
 */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public violations: string[] = [],
    public requestId?: string,
    public retryAfter?: number,
  ) {
    super(code)
  }
}

type Json = Record<string, unknown>

export function readCookie(name: string): string | undefined {
  return document.cookie
    .split('; ')
    .find((c) => c.startsWith(name + '='))
    ?.substring(name.length + 1)
}

export async function ensureCsrf(force = false): Promise<void> {
  if (!force && readCookie('XSRF-TOKEN')) return
  await fetch('/api/v1/auth/csrf', { credentials: 'same-origin' })
}

export async function api<T = unknown>(path: string, options: { method?: string; body?: Json } = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (options.body) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') {
    await ensureCsrf()
    const token = readCookie('XSRF-TOKEN')
    if (token) headers['X-XSRF-TOKEN'] = decodeURIComponent(token)
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: options.body ? JSON.stringify(options.body) : undefined,
  })
  if (res.ok) return (res.status === 204 ? undefined : await res.json()) as T

  let data: { code?: string; violations?: string[]; requestId?: string } = {}
  try {
    data = await res.json()
  } catch {
    /* cuerpo vacio */
  }
  const retry = res.headers.get('Retry-After')
  throw new ApiError(res.status, data.code ?? 'UNKNOWN', data.violations ?? [], data.requestId, retry ? Number(retry) : undefined)
}

const MESSAGES: Record<string, string> = {
  INVALID_CREDENTIALS: 'Credenciales inválidas.',
  RATE_LIMITED: 'Demasiados intentos. Espere unos minutos e intente de nuevo.',
  MFA_FAILED: 'Código incorrecto o expirado. Vuelva a ingresar.',
  MFA_CODE_INVALID: 'El código no es válido.',
  REAUTH_FAILED: 'La contraseña actual no es correcta.',
  VALIDATION_FAILED: 'Revise los datos ingresados.',
  PASSWORD_REJECTED: 'La nueva contraseña no es aceptable.',
  FORBIDDEN: 'No tiene permiso para esta acción.',
  UNAUTHENTICATED: 'Su sesión expiró. Ingrese nuevamente.',
  INTERNAL_ERROR: 'Ocurrió un error. Si persiste, indique este código a soporte.',
}
const PASSWORD_VIOLATIONS: Record<string, string> = {
  PASSWORD_TOO_SHORT: 'Es demasiado corta (use una frase de al menos 15 caracteres).',
  PASSWORD_TOO_LONG: 'Es demasiado larga.',
  PASSWORD_COMMON: 'Es una contraseña muy común.',
  PASSWORD_CONTAINS_CONTEXT: 'Contiene su nombre, correo o el nombre del sistema.',
  PASSWORD_BREACHED: 'Apareció en filtraciones de datos conocidas; elija otra.',
  PASSWORD_REUSED: 'Debe ser distinta de la actual.',
}

export function messageFor(e: unknown): string {
  if (!(e instanceof ApiError)) return 'No se pudo conectar con el servidor.'
  const base = MESSAGES[e.code] ?? MESSAGES.INTERNAL_ERROR
  const extra = e.violations.map((v) => PASSWORD_VIOLATIONS[v] ?? v).join(' ')
  const ref = e.requestId && e.status >= 500 ? ` (ref. ${e.requestId})` : ''
  return [base, extra].filter(Boolean).join(' ') + ref
}
