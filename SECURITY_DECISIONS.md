# Decisiones de seguridad — {{PROJECT_NAME}}

> Registro vivo (la plantilla exige mantenerlo). Fecha de creación: {{DATE}} · Plantilla: ver `.template/VERSION`.
> Regla: toda excepción a un requisito, todo parámetro elegido y todo riesgo aceptado se anota aquí con fecha y responsable.

## 0. Ficha del proyecto (completar)

| Campo | Valor |
|---|---|
| Stack | Java 21 · Spring Boot 4.1 · Spring Security 7 · Spring Session JDBC · PostgreSQL · Flyway · Vue 3 + TS |
| Tipo de cliente | SPA (Vue) + API REST, mismo origen detrás de nginx |
| ¿Multi-tenant / multi-local? | Multi-tenant por `tenant_id` (comercio). *Local/sucursal: definir* |
| Proveedor de identidad | Propio (contraseña + TOTP). Passkeys: pendiente |
| Datos sensibles que maneja | *(completar)* |
| Entorno de despliegue | *(completar: local, VPS, nube; país/región)* |
| Nivel ASVS objetivo | **L2** (L3 para módulos con dinero o datos sensibles) |
| Responsable de seguridad / privacidad (DPO) | *(nombre y contacto)* |
| RPO / RTO | *(definir; ver `docs/operations/BACKUPS.md`)* |

## 1. Decisiones de la base (heredadas de la plantilla)

| # | Decisión | Parámetros / motivo | Evidencia |
|---|---|---|---|
| D1 | Hash de contraseñas **Argon2id** | m=19456 KiB, t=2, p=1 (mínimo OWASP). **Re-medir en el servidor real** (objetivo < 1 s) y anotar el valor aquí | `PasswordHasherTest`; `StartupValidator` impide bajar del mínimo |
| D2 | Política de contraseñas NIST 800-63B | mín. 15, máx. 128, sin composición ni caducidad, lista de bloqueo + HIBP (k-anonimato) + contexto | `PasswordPolicyTest` |
| D3 | HIBP **fail-open** (`hibp-fail-closed=false`) | Si HIBP no responde se permite el cambio y se registra una advertencia. Riesgo aceptado: disponibilidad > comprobación. Cambiar a `true` si el proyecto lo exige | — |
| D4 | Sesión con cookie `__Host-SESSION` en servidor (Spring Session JDBC) | ID de 256 bits; inactividad 2 h (20 min privilegiados); absoluto 10 h; revocable por usuario | `AuthFlowIT` |
| D5 | Sin JWT | Cookie de sesión HttpOnly + CSRF es más simple y revocable para SPA con backend propio | — |
| D6 | Bloqueo de cuenta **temporal** con backoff (5 fallos → 30 s·2ⁿ, máx. 15 min) | Evita DoS por bloqueo permanente; respuesta idéntica al cliente | `AuthFlowIT#temporaryLockout…` |
| D7 | Limitador de tasa **en memoria** | Válido para 1 instancia. **Con varias instancias** reemplazar por limitador compartido (Redis/BD) | `RateLimitIT` |
| D8 | MFA TOTP obligatorio para roles con `mfa_required` (superadmin, admin, gestor) | Compuerta: sin MFA solo puede enrolarlo. Passkeys/WebAuthn: **pendiente** (P1) | `AuthFlowIT#privilegedRole…` |
| D9 | Alta de usuarios con **clave temporal de un solo uso** mostrada al administrador | Excepción temporal hasta tener invitaciones por email; fuerza cambio y MFA en el primer ingreso | `AuthorizationIT#createdUser…` |
| D10 | **Sin recuperación de cuenta self-service** en la base | Un login fuerte con recuperación débil es débil. Al agregarla: tokens ≥128 bits, un uso, 15–30 min, hash en BD, revocar sesiones, notificar (sección 3.5) | — |
| D11 | Auditoría solo-inserción en la misma BD (trigger + sin UPDATE/DELETE al usuario de la app) | **Pendiente**: enviar copia a almacén separado (la app no debe poder borrarlo) | `PlatformIT#auditLog…` |
| D12 | Superadmin inicial por *bootstrap* con clave aleatoria en archivo 0600 | Nunca en logs ni en variables de entorno | `BootstrapAdminRunner` |
| D13 | GitHub Actions por etiqueta mayor (`@v4`) | Dependabot las mantiene. Endurecimiento posible: fijar por SHA de commit | — |

## 2. Excepciones y riesgos aceptados del proyecto

| Fecha | Requisito | Excepción / riesgo | Justificación | Responsable | Revisar el |
|---|---|---|---|---|---|
| | | | | | |

## 3. Ubicación de datos y proveedores (Ley 7593: transferencias internacionales)

| Proveedor / servicio | Qué datos recibe | País / región | Contrato / garantías |
|---|---|---|---|
| *(BD, backups, correo, analítica, IA, …)* | | | |

## 4. Historial de cambios de este documento

| Fecha | Cambio |
|---|---|
| {{DATE}} | Creación a partir de la plantilla |
