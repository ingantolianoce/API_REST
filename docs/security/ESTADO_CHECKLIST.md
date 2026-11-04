# Estado del checklist de cierre (sección 16 de la plantilla)

Leyenda: ✅ implementado y probado · 🟡 parcial / con riesgo aceptado (ver `SECURITY_DECISIONS.md`) · ⬜ pendiente · ➖ no aplica a la base.
**Este archivo es del proyecto**: al crear uno nuevo es el punto de partida; mantenerlo con la evidencia real.
Estado de la base v1.0.0 (los workflows de GitHub y las imágenes Docker se validan en el primer push; el resto se ejecutó localmente).

## Identidad
| | Requisito | Evidencia / nota |
|---|---|---|
| ✅ | Contraseñas 15/128, sin composición ni rotación, lista de bloqueo | `PasswordPolicyTest`. 🟡 La lista semilla es pequeña: ampliarla o confiar en HIBP |
| ✅ | Argon2id + rehash en login | `PasswordHasherTest`, `AuthFlowIT#transparentRehash`. ⬜ Medir parámetros en el servidor real |
| ✅ | Respuestas genéricas, rate limit IP+cuenta, bloqueo temporal con backoff | `AuthFlowIT`, `RateLimitIT`. 🟡 Limitador en memoria (1 instancia) |
| ✅ | MFA obligatorio a roles privilegiados; TOTP; códigos de recuperación hash | `AuthFlowIT#privilegedRole…`. ⬜ Passkeys/WebAuthn (P1) |
| ⬜ | Recuperación con tokens de un solo uso | No existe recuperación self-service (D10). Reset por administrador: pendiente |
| ✅ | Cambio de clave revoca todas las sesiones | `AuthFlowIT#passwordChange…`. ⬜ Notificación por email (`SecurityNotifier` es un stub) |
| ✅ | Sin credenciales por defecto; bootstrap seguro | `BootstrapAdminRunner`, `PlatformIT#seedHas…` |
| ⬜ | Verificación de email / invitaciones por email | Alta con clave temporal (D9) |

## Sesiones y tokens
| | Requisito | Evidencia / nota |
|---|---|---|
| ✅ | ID ≥128 bits, `__Host-`/Secure/HttpOnly/SameSite, regeneración | `AuthFlowIT`; verificado con `curl` contra el jar |
| ✅ | Timeouts inactividad y absoluto; logout invalida; revocación | `SessionService`, `AbsoluteTimeoutFilter`. ⬜ Pantalla "mis sesiones" para revocar por dispositivo (P1). ⬜ Test del timeout absoluto |
| ➖ | JWT | No se usa (D5). Si un proyecto lo agrega: RFC 8725 completo |

## Autorización
| | Requisito | Evidencia / nota |
|---|---|---|
| ✅ | Denegar por defecto; verificación central; permisos granulares | `SecurityConfig`, `ArchitectureTest` |
| ✅ | Anti-IDOR / multi-tenant desde la sesión | `AuthorizationIT#idor…`. ⬜ RLS en PostgreSQL (P2) |
| ✅ | Anti mass assignment y anti-escalada; último superadmin | `AuthorizationIT` |
| 🟡 | Reautenticación en acciones sensibles | Hecho en cambio de clave y MFA; ⬜ cambio de roles, exportaciones |
| ✅ | Matriz rol × endpoint en CI | `AuthorizationIT#roleByEndpointMatrix`, `ci.yml` |

## Aplicación y plataforma
| | Requisito | Evidencia / nota |
|---|---|---|
| ✅ | SQL parametrizado, validación por esquema, errores sin eco | `JdbcClient`, `AuthorizationIT#validationErrors…` |
| ✅ | CSRF, CORS restrictivo, cabeceras, HSTS | `AuthFlowIT`, `PlatformIT`, `nginx.conf` |
| ➖ | Subida de archivos / SSRF | La base no los usa. Si se agregan: aplicar sección 6 |
| ✅ | Secretos fuera del repo con escaneo | `.gitignore`, `.gitleaks.toml`, `security.yml` |
| 🟡 | Cifrado en reposo | Campo TOTP cifrado (AES-GCM). ⬜ Cifrado de disco/volumen y de backups según despliegue |
| ✅ | BD con privilegios mínimos, no expuesta | `db/roles.sql`, `R__grants.sql`, compose `127.0.0.1`. ⬜ TLS a la BD fuera de localhost |
| ⬜ | Backups cifrados y restauración probada | Política en `docs/operations/BACKUPS.md`; implementar por proyecto |
| ✅ | Modo debug off, errores genéricos | `application.yml`, `GlobalExceptionHandler` |

## Operación
| | Requisito | Evidencia / nota |
|---|---|---|
| ✅ | Auditoría solo-inserción de eventos de seguridad y cambios de roles | `PlatformIT`, `AuthorizationIT` |
| 🟡 | Logs sin datos sensibles; alertas | Logs JSON saneados. ⬜ Almacén separado y alertas (ráfagas, 403/429/500, cambios de rol) |
| 🟡 | CI con SAST, dependencias, secretos y tests | Workflows escritos; ⬜ confirmar la primera ejecución en GitHub |
| ⬜ | Plan de respuesta a incidentes y parcheo | Plantillas: `docs/operations/RUNBOOK_INCIDENTES.md`; completar contactos |

## Legal Paraguay (sección 19)
| | Requisito | Evidencia / nota |
|---|---|---|
| 🟡 | Consentimientos versionados; solicitudes de titulares | Tablas `consents`, `data_subject_requests`. ⬜ Endpoints/pantallas, exportar y anonimizar, plazo de 30 días |
| ⬜ | Inventario de datos, retención automática | `docs/privacy/INVENTARIO_DATOS.md` (plantilla) |
| ⬜ | Notificación de incidentes ≤ 72 h | Runbook plantilla; definir contactos y probar |
| ⬜ | Ubicación de datos/proveedores; contratos con encargados; DPO | `SECURITY_DECISIONS.md` §3 |
| ⬜ | Revisión legal confirmada por abogado | Pendiente |
