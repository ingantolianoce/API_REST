# Runbook de respuesta a incidentes (plantilla)

> Accesible **fuera del sistema** (impreso / otro almacenamiento). Completar contactos y probar con un simulacro cada 6 meses.
> **Ley 7593/2025: notificar a la ANPDP y a los titulares afectados dentro de 72 horas desde que se tuvo conocimiento** (confirmar con el reglamento).

## Roles
| Rol | Persona | Contacto 24/7 |
|---|---|---|
| Líder del incidente (decide) | | |
| Técnico de contención | | |
| Responsable de privacidad / DPO | | |
| Comunicación a clientes / titulares | | |
| Asesor legal | | |

## Severidad
| Nivel | Criterio | Reacción |
|---|---|---|
| SEV1 | Filtración de datos personales, acceso no autorizado confirmado, ransomware | Inmediata; arranca el reloj de 72 h |
| SEV2 | Cuenta privilegiada comprometida, vulnerabilidad explotable sin evidencia de uso | ≤ 4 h |
| SEV3 | Intento fallido, vulnerabilidad sin explotación | Siguiente día hábil |

## Pasos
1. **Detectar y registrar la hora de conocimiento** (inicio del plazo de 72 h). Abrir bitácora.
2. **Contener**: revocar sesiones (`SessionService.revokeAll` / borrar filas de `spring_session`), deshabilitar cuentas (`POST /api/v1/users/{id}/disable`), rotar secretos (`APP_CRYPTO_KEY` implica re-enrolar MFA; contraseñas de BD), bloquear IPs en el proxy, aislar el host. **No borrar evidencia**.
3. **Preservar evidencia**: copia de `audit_log` (solo-inserción), logs HTTP/aplicación, imágenes de disco; cadena de custodia.
4. **Evaluar alcance** con la auditoría: qué datos, de qué titulares, qué tenants (`audit_log` por `tenant_id`/`event`/`occurred_at`; accesos a datos personales).
5. **Erradicar y recuperar**: parchear, restaurar desde backup limpio (`RUNBOOK_RECUPERACION.md`), forzar cambio de contraseñas y re-enrolamiento de MFA si hubo compromiso de credenciales.
6. **Notificar** (≤ 72 h): ANPDP y titulares afectados. Contenido: naturaleza del incidente, datos y personas afectadas, consecuencias probables, medidas tomadas, contacto. Informar también a los comercios (responsables) si somos encargados.
7. **Post-mortem** (≤ 10 días): causa raíz, línea de tiempo, acciones; actualizar controles, tests y la plantilla (`CICLO_DE_ACTUALIZACION.md`).

## Indicadores a vigilar (alertas a configurar)
Ráfagas de `auth.login.failed`; `auth.login.password_ok` tras muchos fallos; picos de 403/429/500; `user.roles.changed` fuera de horario;
`auth.mfa.failed` repetido; uso de códigos de recuperación; exportaciones masivas; fallo de backup.
