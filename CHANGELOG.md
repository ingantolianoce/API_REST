# Changelog de la plantilla de seguridad

Formato: [SemVer](https://semver.org/lang/es/). **MAJOR** = cambia/agrega un requisito P0 o rompe compatibilidad;
**MINOR** = control nuevo o mejora; **PATCH** = correcciones y documentación.
Cada entrada separa lo que `scripts/template-sync.sh` aplica solo (**Documentos / CI**) de lo que hay que aplicar a mano (**Código base**).
Las actualizaciones **CRÍTICAS** (vulnerabilidad en el diseño o el código base) se marcan así y se propagan en ≤ 7 días.

## [1.0.0] — 2026-11-04

Primera versión. Basada en `SEGURIDAD_USUARIOS_ROLES.md` v1.2 (nov. 2026).

### Documentos / CI
- Especificación completa y versión compacta (`docs/security/`), guía de stack, checklist con evidencia, ciclo de actualización.
- Runbooks (incidentes 72 h, recuperación), política de respaldos, inventario de datos (Ley 7593).
- CI (tests, CodeQL, gitleaks, npm audit, OSV, dependency-review), Dependabot, avisos de actualización y revisión trimestral.

### Código base
- Backend Spring Boot 4.1 / Security 7: cadena deny-by-default, CSRF, CORS en lista blanca, cabeceras, cookie `__Host-SESSION`
  (ID 256 bits), timeouts por inactividad y absoluto, revocación de sesiones.
- Argon2id con rehash transparente, política de contraseñas NIST (incl. HIBP), bloqueo temporal, hash señuelo, rate limit.
- MFA TOTP con códigos de recuperación (hash) y compuertas de cuenta; secreto TOTP cifrado AES-256-GCM.
- RBAC por permisos + tenant desde la sesión, anti-IDOR, anti mass assignment, anti-escalada, último superadmin protegido.
- Auditoría solo-inserción, logs JSON con `request_id`, manejo de errores genérico, bootstrap seguro del primer superadmin.
- Esquema Flyway (identidad, roles, consentimientos, solicitudes de titulares, auditoría) y roles de BD de mínimo privilegio.
- Frontend Vue 3: login, MFA, cambio de clave, CSRF, sin tokens en el navegador; nginx con CSP estricta.
- 56 pruebas backend (unitarias, integración con PostgreSQL real, arquitectura) y 6 de frontend.

### Pendiente conocido (ver `docs/security/ESTADO_CHECKLIST.md`)
Passkeys, recuperación y verificación de email, notificaciones por email, almacén de auditoría separado, alertas, rate limit
distribuido, exportación/anonimización de titulares, retención automática, backups implementados (solo política/documentación).
