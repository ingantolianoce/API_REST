# Reglas de seguridad del proyecto (versión compacta)

> Resumen operativo de `SEGURIDAD_USUARIOS_ROLES.md` (referencia completa). Pegar en el `CLAUDE.md` del proyecto o importarlo. Al aplicarla: adaptar al stack, escribir pruebas, y registrar decisiones y excepciones en `SECURITY_DECISIONS.md`. No simplificar los puntos P0; si el stack no los permite, detenerse y reportar.
> Base: OWASP ASVS 5.0 (nivel 2; nivel 3 para dinero/datos sensibles), OWASP Top 10:2025, NIST SP 800-63B Rev. 4, RFC 8725, marco legal de Paraguay.

## Principios
- Denegar por defecto; autorización siempre en el servidor, en un punto central; mínimo privilegio; fallar cerrado (ante error, acceso denegado).
- Usar librerías maduras de auth/hash/sesión del stack. Nada de criptografía propia.
- Nunca secretos en el repositorio. Ninguna credencial por defecto.

## Autenticación
- Contraseña: mín. 15 caracteres (8 solo si siempre hay MFA), máx. ≥ 64, permitir espacios/Unicode/pegar. Sin reglas de composición ni caducidad periódica. Bloquear contraseñas comunes o filtradas (k-anonimato HIBP) y las del contexto.
- Hash: **Argon2id** (m=19456 KiB, t=2, p=1 como mínimo). Alternativas: scrypt (N=2^17, r=8, p=1), bcrypt ≥ 10 (límite 72 bytes), PBKDF2-SHA256 ≥ 600.000 si exige FIPS. Rehash transparente en login. Comparaciones en tiempo constante.
- Fuerza bruta: rate limit por IP y por cuenta, backoff/bloqueo temporal (no permanente), respuestas genéricas sin enumerar usuarios, `429`.
- MFA obligatorio para roles admin/gestión; preferir passkeys (WebAuthn); TOTP como alternativa; evitar SMS; códigos de recuperación hasheados. Reautenticación en acciones sensibles.
- Recuperación: tokens ≥ 128 bits, un solo uso, 15–30 min, guardados como hash; al cambiar contraseña revocar todas las sesiones y notificar. La recuperación no debe degradar la seguridad del login.

## Sesiones y tokens
- ID ≥ 128 bits CSPRNG; cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax/Strict`; regenerar al login y al cambiar privilegios; logout invalida en servidor; timeouts por inactividad y absoluto; revocación por dispositivo.
- JWT (solo si hace falta): fijar algoritmo, rechazar `none`, validar `iss`/`aud`/`exp`/`typ`, access 5–15 min, refresh rotativo con detección de reutilización, nada sensible en el payload.

## Autorización
- Permisos granulares `recurso:accion`; los roles agrupan permisos; el código verifica permisos.
- RBAC + propiedad/ámbito: nunca buscar solo por ID (anti-IDOR); `tenant_id` sale de la sesión, nunca del cliente; filtro global por tenant (o RLS).
- Anti mass assignment (lista blanca de campos; nunca `role`, `tenant_id`, `status` desde el cliente). Nadie edita sus propios roles; solo se asigna lo que se posee; proteger al último superadmin.
- Tests automáticos de la matriz rol × endpoint en CI.

## Aplicación y plataforma
- Consultas parametrizadas, validación por esquema en servidor, escape de salida, control de SSRF y de subida de archivos.
- HTTPS + HSTS; CSRF (SameSite + token); CORS con lista blanca; CSP estricta, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors`; `Cache-Control: no-store` en datos sensibles.
- Errores genéricos al usuario con ID de correlación; modo debug apagado en producción.
- Dependencias con lockfile, escaneo (SCA, SAST, secretos) en CI; revisión de código para auth/authz/cripto.
- BD no expuesta, usuario de aplicación con mínimos privilegios, TLS fuera de localhost.

## Datos mínimos por entidad
- Todas las tablas: `id` (UUID/ULID), `tenant_id`, `created_at/by`, `updated_at/by`, `deleted_at`, `version`. Fechas UTC; importes enteros (PYG sin decimales).
- Comercio: razón social, RUC, datos fiscales, dirección/contacto, locales/cajas, moneda, plan, estado, responsable de privacidad.
- Usuario: nombre, email único, `password_hash`, estado, MFA/passkeys, roles por comercio/local, intentos y bloqueo, ciclo de vida (alta, baja, motivo).
- Cliente: tipo, nombre/razón social, CI/RUC, contacto, consentimientos versionados; crédito solo si aplica (Ley 6534). No pedir datos sensibles sin necesidad y base legal (cifrar por campo).
- Transacción: ítems con precio e impuestos congelados, estado, usuario/caja, **anular con motivo y autor, nunca borrar**; no guardar PAN/CVV (token y últimos 4).

## Logs
- JSON estructurado con `timestamp` UTC, `event`, `tenant_id`, `user_id`, `ip`, `request_id`, `resource`, `action`, `result`. Nunca contraseñas, tokens, PAN/CVV ni datos personales innecesarios.
- Obligatorios: auditoría de seguridad (login, MFA, roles, 403), auditoría de negocio (cambios con valor anterior/nuevo, anulaciones), acceso/exportación de datos personales, técnico, HTTP, BD y cambios de esquema, infraestructura, integraciones.
- Auditoría solo-inserción, en almacén separado, con relojes sincronizados y alertas (ráfagas de fallos, picos 403/429/500, cambios de rol atípicos, exportaciones masivas, fallo de backup).
- Retención sugerida: auditoría de seguridad 12 meses en línea + archivo; técnicos 30–90 días; plazos fiscales/legales a confirmar.

## Respaldos
- Definir RPO/RTO por proyecto. Regla 3-2-1-1-0 (3 copias, 2 medios, 1 externa, 1 inmutable/offline, 0 errores de restauración).
- Completa + incrementales + archivado continuo (PITR: WAL/binlog). Cifrado AES-256 con claves separadas. Usuario de backup con mínimos privilegios; la producción no puede borrar las copias.
- Restauración automática probada cada mes y simulacro completo cada 6 meses con RTO medido. Alerta si falla un backup. Retención GFS (14 diarias, 8 semanales, 12 mensuales) ajustada a la ley.
- Lista de supresiones que se reaplica al restaurar. Runbook de recuperación fuera del sistema. En POS locales: copia local + copia externa cifrada + UPS.

## Marco legal de Paraguay (resumen)
- **Ley 7593/2025** (datos personales): promulgada 27-nov-2025, exigible en nov. 2027; **diseñar ya conforme a ella**. Implementar: base legal y consentimiento versionado, aviso de privacidad, derechos (acceso, rectificación, supresión, oposición, portabilidad) con respuesta ≤ 30 días, **notificación de incidentes ≤ 72 h**, minimización y retención automática, protección reforzada de datos sensibles y de menores, garantías para transferencias internacionales, contratos con encargados, contacto de privacidad/DPO.
- **Ley 6534/2020** (datos crediticios, vigente): finalidad limitada, prohibido para decisiones laborales, retención de datos adversos ≤ 5 años, auditar consultas.
- **Ley 6822/2021** (firma electrónica y servicios de confianza): distinguir firma electrónica de **cualificada**; guardar hash, sello de tiempo y evidencia de aceptación en documentos con efecto legal.
- **Ley 4868/2013** (comercio electrónico): información clara al consumidor, conservar evidencia de aceptación, comprobante/factura electrónica (verificar requisitos DNIT/SIFEN con el contador).
- **Código Penal (Ley 4439/2011)**: pruebas de seguridad solo con autorización escrita; conservar auditoría íntegra como evidencia.
- No es asesoría legal: validar con un abogado, y revisar al publicarse el decreto reglamentario de la Ley 7593.

## Definición de terminado (por funcionalidad)
1. Requisitos P0 aplicables cumplidos y probados (tests de seguridad incluidos).
2. Sin secretos ni datos personales en logs ni en el repositorio.
3. Autorización verificada para cada endpoint nuevo (casos permitido/denegado/IDOR).
4. Dependencias escaneadas y sin vulnerabilidades críticas.
5. Decisiones, parámetros y excepciones anotados en `SECURITY_DECISIONS.md`.
