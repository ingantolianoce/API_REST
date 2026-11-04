# Guía de stack: Spring Boot · PostgreSQL · Vue

Traduce `SEGURIDAD_USUARIOS_ROLES.md` (sección → requisito) a **dónde está implementado** en este stack y **qué prueba lo verifica**.
Versiones de la base: Java 21, Spring Boot 4.1.x (Spring Security 7, Spring Session 4), PostgreSQL 17, Flyway, Vue 3.5, Vite 7.
Rutas del backend relativas a `backend/src/main/java/<paquete>/`; pruebas en `backend/src/test/java/<paquete>/`.

## Mapa requisito → implementación → prueba

| Sec. | Requisito | Implementación | Prueba |
|---|---|---|---|
| 1 | Denegar por defecto | `config/SecurityConfig` (`anyRequest().authenticated()`) + `@EnableMethodSecurity` | `AuthFlowIT#unauthenticatedRequests…` |
| 1,5 | Todo endpoint declara su permiso | `@PreAuthorize` obligatorio | `arch/ArchitectureTest` (rompe el build) |
| 5 | El código verifica **permisos**, no roles | autoridades = `recurso:accion` (`security/AppUserDetails`); regla ArchUnit contra `hasRole` | `ArchitectureTest#noRoleNameChecksInCode` |
| 2 | Esquema de identidad, UUID, borrado lógico | `resources/db/migration/V1__identity.sql` | `PlatformIT` |
| 3.1 | Política de contraseñas (15/128, sin composición, bloqueo, HIBP) | `security/PasswordPolicy`, `HibpBreachedPasswordChecker`, `resources/common-passwords.txt` | `unit/PasswordPolicyTest` |
| 3.2 | Argon2id + rehash + señuelo + límite de concurrencia | `security/PasswordHasher`; mínimos en `config/StartupValidator` | `PasswordHasherTest`, `AuthFlowIT#transparentRehash…` |
| 3.3 | Respuestas genéricas, rate limit, bloqueo temporal | `auth/LoginService`, `common/RateLimiter`, SQL atómico en `UserRepository#registerFailedAttempt` | `AuthFlowIT`, `RateLimitIT` |
| 3.4 | MFA TOTP, códigos de recuperación hash, anti-reutilización | `auth/MfaService`, `security/TotpService`, `auth/RecoveryCodes` | `AuthFlowIT#privilegedRole…`, `TotpServiceTest` |
| 3.4 | MFA obligatorio a roles privilegiados | `roles.mfa_required` + `security/AuthenticatedRequestFilter` (compuerta) | `AuthFlowIT#privilegedRole…` |
| 3.5 | Sin credenciales por defecto; bootstrap | `config/BootstrapAdminRunner` | `PlatformIT#seedHasNoUsers…`, prueba manual (README) |
| 3.5 | Cambio de clave revoca sesiones y exige reautenticación | `auth/AccountService#changePassword` | `AuthFlowIT#passwordChangeRevokesAllSessions…` |
| 4.1 | Cookie `__Host-`, Secure, HttpOnly, SameSite; ID ≥128 bits | `config/SessionConfig` (ID 256 bits) | `AuthFlowIT#loginSetsHardenedSessionCookie` |
| 4.1 | Regenerar ID; logout real; timeouts | `auth/SessionService`, `security/AbsoluteTimeoutFilter` | `AuthFlowIT#sessionIdIsRegenerated…`, `#logoutInvalidates…` |
| 5 | Anti-IDOR, tenant desde la sesión | `UserRepository` (siempre `tenant_id`), `UserService#requireInTenant` → 404 | `AuthorizationIT#idor…` |
| 5 | Mass assignment | DTOs `record` + `spring.jackson.deserialization.fail-on-unknown-properties` | `AuthorizationIT#massAssignment…` |
| 5 | Anti-escalada, no auto-editar roles, último superadmin | `user/UserService` | `AuthorizationIT#noPrivilegeEscalation`, `#nobodyEdits…`, `#lastSuperadmin…` |
| 5 | Matriz rol × endpoint en CI | `AuthorizationIT#roleByEndpointMatrix` + `ci.yml` | idem |
| 6 | SQL parametrizado | `JdbcClient` con parámetros con nombre | `ArchitectureTest` (controladores no usan JDBC) |
| 6 | Validación en servidor, errores sin eco de entrada | Bean Validation + `common/GlobalExceptionHandler` | `AuthorizationIT#validationErrors…` |
| 7 | CSRF (cookie + cabecera), CORS lista blanca | `SecurityConfig`; `frontend/src/api/http.ts` | `AuthFlowIT#csrfTokenIsRequired…`, `PlatformIT#cors…` |
| 7 | Cabeceras (CSP, HSTS, nosniff, Referrer, Permissions, COOP/CORP), `no-store` | `SecurityConfig`; `frontend/nginx.conf` para la SPA | `PlatformIT#securityHeaders…` |
| 7 | Límite de tamaño de cuerpo | `common/BodySizeLimitFilter` + `client_max_body_size` en nginx | — |
| 8 | Secretos fuera del repo, cifrado de campos | variables de entorno sin defaults; `security/FieldEncryptor` (AES-256-GCM con AAD) | `FieldEncryptorTest`; `security.yml` (gitleaks) |
| 8 | Falla al arrancar si la config es insegura | `config/StartupValidator` | arranque |
| 10 | BD con mínimo privilegio, migrador separado | `db/roles.sql`, `R__grants.sql` | `PlatformIT#applicationDbUserHasNoDdl…` |
| 11 | Auditoría solo-inserción, saneada, con `request_id` | `audit/AuditService`, trigger en `V1` | `PlatformIT#auditLogIsAppendOnly…`, `AuthorizationIT#roleChangeAudit…` |
| 11,20.2 | Logs JSON estructurados | `resources/logback-spring.xml`, `common/RequestIdFilter` | `PlatformIT#requestId…` |
| 12 | Errores genéricos + ID de correlación; fallar cerrado | `GlobalExceptionHandler`; `StartupValidator` | `AuthorizationIT`, `PlatformIT` |
| 13 | Lockfiles, SCA, SAST, secretos en CI | `package-lock.json`, `ci.yml`, `security.yml`, Dependabot | CI |
| 19 | Consentimientos, solicitudes de titulares (esquema) | tablas `consents`, `data_subject_requests` | pendiente de lógica (ver checklist) |

## Recetas

### Bootstrap del primer superadmin
```bash
cp .env.example .env     # completar; APP_BOOTSTRAP_ENABLED=true, APP_BOOTSTRAP_ADMIN_EMAIL, APP_BOOTSTRAP_TENANT_NAME
docker compose up -d db && (cd backend && mvn spring-boot:run)   # usar variables de .env
cat .local/bootstrap/admin-credentials.txt   # leer la clave de un solo uso y BORRAR el archivo
# volver a APP_BOOTSTRAP_ENABLED=false
```
El primer ingreso fuerza **cambio de clave** y **alta de MFA** (superadmin tiene `mfa_required`).

### Nuevo endpoint (patrón)
Copiar `user/UserController` + `user/UserService`: `@PreAuthorize("hasAuthority('x:y')")`, DTO `record` con validación, tenant del principal,
`findByIdAndTenant`, auditoría en la misma transacción. Añadir casos a `AuthorizationIT` (matriz, IDOR, validación).

### Nuevo permiso / rol
Migración `V3__...sql` con `INSERT INTO permissions` / `roles` / `role_permissions`. Asignación solo vía `UserService` (anti-escalada).

### Varias instancias del backend
Reemplazar `common/RateLimiter` por una implementación compartida (Redis o tabla) y revisar `server.tomcat.remoteip.internal-proxies`.
Las sesiones ya están en PostgreSQL (Spring Session JDBC), así que cualquier instancia las ve y las puede revocar.

### Reautenticación en acciones sensibles
Hoy exigen contraseña actual: cambio de clave y alta de MFA. Para nuevas acciones críticas (exportaciones, cambios de rol) agregar el mismo
patrón (`AccountService`/`MfaService`: `hasher.matches` + `limiter`) o un TTL "reautenticado hace < 5 min" en sesión.

### Frontend
* Cookie HttpOnly: **no** guardar tokens en `localStorage`. `v-html` prohibido con datos de usuario. CSP por cabecera (nginx), sin estilos/scripts en línea.
* `auth.can('x:y')` solo oculta opciones: el servidor decide.
* Desarrollo: Vite reenvía `/api` al backend (un solo origen ⇒ sin CORS). Cookies `__Host-`: usar Chrome/Firefox en `localhost` o HTTPS local.
* QR del TOTP: generar localmente (sin servicios externos) a partir de `otpauthUri`; hoy se muestra la clave en texto.

### Producción (lista breve)
TLS terminado en el proxy (HSTS), `server.forward-headers-strategy=native` + `server.tomcat.remoteip.internal-proxies` con las IPs reales del proxy,
usuario de BD `app_runtime` con TLS (`sslmode=verify-full`), `APP_CRYPTO_KEY` desde el gestor de secretos, logs a un almacén separado, backups
(`docs/operations/BACKUPS.md`), modo debug apagado (no existe `dev` por defecto), consola de BD no pública.
