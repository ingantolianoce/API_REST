# Plantilla de seguridad para sistemas con usuarios y roles

> **Uso:** este documento es una especificación genérica, independiente del stack, para aplicar en cualquier sistema de gestión con usuarios, roles y permisos (web, API, escritorio con backend). Al aplicarla en un proyecto, el agente debe: (1) leer el proyecto, (2) completar la sección 0, (3) implementar cada requisito adaptándolo al stack real, (4) marcar el checklist de la sección 16 con evidencia (archivo/test), y (5) listar lo que no pudo aplicar y por qué.

**Base normativa (verificada, nov. 2026):** OWASP ASVS 5.0 (mayo 2025, 17 capítulos), OWASP Top 10:2025, NIST SP 800-63B Rev. 4 (jul./ago. 2025), OWASP Cheat Sheets (Password Storage, Session Management, Authentication, Authorization), RFC 8725 (buenas prácticas JWT).

**Nivel objetivo:** ASVS **Nivel 2** como mínimo para todo proyecto. **Nivel 3** para módulos con dinero, datos personales sensibles, salud o administración global.

**Prioridades:** `[P0]` obligatorio, bloquea el despliegue · `[P1]` requerido antes de producción · `[P2]` recomendado / madurez.

---

## 0. Ficha del proyecto (completar al aplicar)

| Campo | Valor |
|---|---|
| Stack (lenguaje, framework, BD) | |
| Tipo de cliente (web SPA, SSR, móvil, escritorio, API-only) | |
| ¿Multi-tenant / multi-local? | |
| Proveedor de identidad (propio / OIDC externo) | |
| Datos sensibles que maneja | |
| Entorno de despliegue (local, VPS, nube) | |
| Nivel ASVS objetivo | L2 / L3 |

**Regla de decisión:** si existe un framework de autenticación/autorización maduro para el stack, usarlo. No inventar criptografía ni gestión de sesiones propias. (Los fallos de control de acceso son la categoría nº 1 del OWASP Top 10 desde hace más de 20 años, en gran parte por implementaciones caseras.)

---

## 1. Principios de diseño

1. `[P0]` **Denegar por defecto.** Todo recurso, endpoint y acción exige permiso explícito. Si no hay regla que permita, se niega.
2. `[P0]` **Autorización siempre en el servidor.** Ocultar un botón en la interfaz no es control de acceso. Nunca confiar en roles/IDs enviados por el cliente.
3. `[P0]` **Mínimo privilegio** para usuarios, servicios, usuario de base de datos y tokens.
4. `[P0]` **Fallar cerrado.** Ante error, excepción o dato inesperado, el resultado es "acceso denegado", nunca "acceso concedido" (OWASP A10:2025, manejo de condiciones excepcionales).
5. `[P1]` **Defensa en profundidad:** validar en capa de entrada, de servicio y de datos.
6. `[P1]` **Un único punto de decisión de autorización** (middleware/policy central), no `if (rol == ...)` esparcidos.
7. `[P1]` **Secure by default:** configuración inicial segura sin pasos manuales.

---

## 2. Modelo de datos de identidad y permisos

Esquema mínimo (adaptar nombres):

- `users`: `id` (UUID/ULID, no secuencial), `email` (único, normalizado), `password_hash`, `status` (pendiente, activo, bloqueado, desactivado), `email_verified_at`, `mfa_enabled`, `failed_attempts`, `locked_until`, `password_changed_at`, `created_at`, `updated_at`, `deleted_at`.
- `roles`: `id`, `name`, `description`, `is_system`.
- `permissions`: `id`, `code` con formato `recurso:accion` (ej. `invoice:read`, `user:disable`).
- `role_permissions`, `user_roles` (con `tenant_id`/`local_id` si hay multi-tenant).
- `sessions`/`refresh_tokens`: `id`, `user_id`, `token_hash` (nunca el token en claro), `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `ip`, `user_agent`.
- `credentials_passkeys` (si aplica): `credential_id`, `public_key`, `sign_count`, `label`, `last_used_at`.
- `recovery_codes`: solo hashes, un solo uso.
- `audit_log`: ver sección 11 (solo-inserción).

Requisitos:
- `[P0]` Identificadores no predecibles (UUID/ULID) en URLs y APIs.
- `[P0]` Permisos granulares (`recurso:accion`); los roles son **agrupaciones** de permisos y el código verifica **permisos**, no nombres de rol.
- `[P1]` Roles base sugeridos: `superadmin` (mínimas cuentas, MFA obligatorio), `admin`, `gestor`, `operador`, `solo_lectura`. Cada proyecto ajusta.
- `[P1]` Se debe impedir quedarse **sin ningún superadmin** (no permitir desactivar/degradar al último).
- `[P1]` Borrado lógico de usuarios; los registros de auditoría nunca se borran con el usuario.
- `[P2]` Roles de sistema (`is_system`) no editables desde la interfaz.

---

## 3. Autenticación

### 3.1 Contraseñas (NIST 800-63B Rev. 4 + OWASP)
- `[P0]` Longitud mínima **15 caracteres** si la contraseña es el único factor; **8** solo si SIEMPRE hay un segundo factor. Permitir al menos **64** de máximo.
- `[P0]` Aceptar espacios, todo ASCII imprimible y Unicode; contar cada punto de código como un carácter.
- `[P0]` **Sin reglas de composición** (no exigir mayúscula/número/símbolo) y **sin expiración periódica**; solo forzar cambio ante sospecha o evidencia de compromiso.
- `[P0]` **Lista de bloqueo** obligatoria al crear/cambiar contraseña: contraseñas comunes, filtradas en brechas (ej. API k-anonimato de Have I Been Pwned), palabras del contexto (nombre del sistema, usuario, email). Explicar al usuario por qué se rechazó.
- `[P0]` Permitir **pegar** y administradores de contraseñas. Medidor de fortaleza opcional (`[P2]`).
- `[P0]` Prohibidas las preguntas secretas ("nombre de tu mascota").

### 3.2 Almacenamiento de contraseñas (OWASP Password Storage)
Orden de preferencia:
1. **Argon2id** (mín. `m=19456 KiB (19 MiB), t=2, p=1`; equivalentes: `m=47104,t=1`, `m=12288,t=3`, `m=9216,t=4`, `m=7168,t=5`, todos `p=1`).
2. **scrypt** si no hay Argon2id: `N=2^17, r=8, p=1`.
3. **bcrypt** solo en sistemas heredados: factor ≥ 10 y límite de 72 bytes (rechazar o pre-hashear entradas largas).
4. **PBKDF2-HMAC-SHA256** ≥ 600.000 iteraciones solo si se exige FIPS-140.

- `[P0]` Nunca MD5, SHA-1, SHA-256 simple ni cifrado reversible. Sal única por contraseña (la generan las librerías).
- `[P0]` Guardar el hash en formato autodescriptivo (PHC: `$argon2id$v=19$m=...,t=...,p=...$sal$hash`).
- `[P1]` **Rehash transparente** en el siguiente login exitoso si los parámetros quedaron por debajo del objetivo actual.
- `[P1]` Ajustar costo midiendo en el servidor real: apuntar a < 1 s por hash, sin abrir un vector de DoS por CPU/memoria (limitar concurrencia de hashing).
- `[P2]` *Pepper* (secreto aplicado fuera de la BD) guardado en gestor de secretos/HSM, no en el repositorio.
- `[P1]` Comparaciones de secretos en **tiempo constante**. Ejecutar un hash "señuelo" cuando el usuario no existe para igualar tiempos de respuesta.

### 3.3 Protección contra fuerza bruta y relleno de credenciales
- `[P0]` Rate limiting en `/login`, `/registro`, `/recuperar`, `/verificar-mfa` por **IP y por cuenta**.
- `[P0]` Respuesta **genérica** ante fallo ("Credenciales inválidas") sin revelar si el usuario existe; misma forma y similar tiempo de respuesta. Aplica también a registro y recuperación ("Si el correo existe, enviamos instrucciones").
- `[P1]` Retardo exponencial / bloqueo **temporal** (ej. 5 intentos fallidos → espera creciente). Evitar bloqueo permanente automático: permite denegación de servicio contra cuentas ajenas.
- `[P1]` Devolver `429` con `Retry-After` en limitación; alertar a administradores ante picos.
- `[P2]` CAPTCHA/desafío adaptativo tras umbral de fallos; detección de credenciales filtradas.

### 3.4 MFA y passkeys
- `[P0]` MFA **obligatorio** para `superadmin`/`admin` y cualquier rol con permisos de gestión de usuarios o datos sensibles.
- `[P1]` Ofrecer **passkeys (WebAuthn/FIDO2)** como método preferido: resistentes a phishing, vinculadas al origen del dominio. Permitir varias por cuenta; guardar solo clave pública e ID; verificar `origin`, `rpId`, desafío único y contador.
- `[P1]` Alternativa: TOTP (RFC 6238) con ventana ±1 paso, anti-reutilización del código y límite de intentos. Códigos de un solo uso, secreto TOTP cifrado en reposo.
- `[P1]` Evitar SMS como segundo factor (NIST lo considera autenticador restringido); si se usa, solo como opción de baja garantía, nunca como único fallback de cuentas privilegiadas.
- `[P1]` **Códigos de recuperación** de un solo uso, mostrados una vez, guardados como hash.
- `[P1]` **Reautenticación** (contraseña o passkey recientes) antes de acciones sensibles: cambiar email/contraseña/MFA, asignar roles, exportar datos, operaciones financieras.
- `[P2]` Passkeys como método principal y eliminación gradual de contraseñas, solo si la recuperación es igual de robusta (ver 3.5).

### 3.5 Registro, verificación y recuperación de cuenta
La recuperación es el eslabón más débil: un login fuerte con recuperación débil es un login débil.
- `[P0]` Verificar propiedad del email antes de activar la cuenta.
- `[P0]` Tokens de recuperación/verificación: ≥ 128 bits aleatorios criptográficos, **un solo uso**, expiración corta (ej. ≤ 15–30 min), guardados como hash, invalidados al usarse o al emitir uno nuevo.
- `[P0]` Al cambiar la contraseña: **invalidar todas las sesiones y refresh tokens** y notificar por email.
- `[P0]` No crear cuentas con contraseñas por defecto; nada de credenciales por defecto en ningún entorno. Usuario inicial por script de *bootstrap* con contraseña aleatoria de un solo uso y cambio forzado.
- `[P1]` Cambio de email: confirmar en el correo nuevo y avisar al antiguo; reautenticación previa.
- `[P1]` Recuperación de cuentas con MFA: no debe degradar a "solo email"; exigir segundo passkey, código de recuperación o verificación por un administrador con registro de auditoría.
- `[P1]` Invitaciones de alta: enlace de un solo uso con expiración, rol asignado por el invitante solo dentro de su propio alcance.

---

## 4. Gestión de sesiones y tokens

### 4.1 Sesiones con cookie (recomendado para apps web propias)
- `[P0]` ID de sesión generado por CSPRNG, ≥ 128 bits de entropía, opaco; el estado vive en el servidor.
- `[P0]` Atributos de cookie: `Secure; HttpOnly; SameSite=Lax` (o `Strict` si el flujo lo permite). Preferir prefijo `__Host-` (ej. `__Host-session`, con `Path=/`, sin `Domain`).
- `[P0]` **Regenerar** el ID al iniciar sesión y en cada cambio de privilegios (anti fijación de sesión).
- `[P0]` Invalidación real en servidor al cerrar sesión; el token viejo deja de funcionar.
- `[P0]` Nunca poner el ID de sesión en la URL ni en logs.
- `[P1]` Timeouts: **inactividad** (sugerido 15–30 min para roles privilegiados, hasta 2 h para usuarios comunes) y **absoluto** (sugerido 8–12 h); ajustar según riesgo.
- `[P1]` Listar y permitir revocar sesiones activas por dispositivo; revocar todas ante cambio de contraseña, rol o desactivación.
- `[P2]` Vincular sesión a señales de contexto (cambio drástico de IP/agente → reautenticar), sin romper a usuarios móviles.

### 4.2 Tokens (JWT / API / refresh) — solo si hay razón (APIs, móviles, microservicios)
Aplicar RFC 8725:
- `[P0]` **Fijar el algoritmo** en el servidor (ej. EdDSA, ES256, RS256 o HS256 con secreto ≥ 256 bits); rechazar `none` y nunca confiar en el `alg` del encabezado; no mezclar claves simétricas y asimétricas.
- `[P0]` Validar siempre `iss`, `aud`, `exp`, `nbf` (tolerancia de reloj ≤ 30 s) y el tipo de token (`typ`, ej. `at+jwt`); reglas separadas para tipos distintos (un token de identidad no sirve como token de acceso).
- `[P0]` Access token de vida **corta** (ej. 5–15 min); refresh token **rotativo**, de un solo uso, guardado como hash, con detección de reutilización (si se reutiliza, revocar toda la familia).
- `[P0]` Nada sensible en el payload (el JWT va firmado, no cifrado). Los permisos efectivos se consultan/validan en servidor, no se confía ciegamente en claims de rol antiguos.
- `[P1]` Almacenamiento en navegador: preferir cookie `HttpOnly` sobre `localStorage`. Si se usa cabecera `Authorization`, mitigar XSS con CSP estricta.
- `[P1]` Mecanismo de revocación (lista de `jti` revocados o versión de token por usuario).
- `[P1]` Claves en gestor de secretos, con rotación y `kid` para múltiples claves vigentes.

### 4.3 OAuth 2.0 / OIDC (si se integra SSO)
- `[P0]` Authorization Code + **PKCE**; no usar flujos implícito ni de contraseña. Validar `state` y `nonce`; `redirect_uri` con coincidencia exacta (sin comodines).
- `[P1]` Mapear roles/permisos del IdP a roles locales de forma explícita; no conceder admin por claims no verificados.

---

## 5. Autorización (control de acceso)

- `[P0]` **Verificar en cada solicitud**, en el servidor, en un componente central. Cubrir endpoints de API, vistas, acciones en segundo plano, WebSockets, descargas de archivos, exportaciones, reportes y tareas programadas.
- `[P0]` **Modelo híbrido RBAC + propiedad/atributos (ABAC):** RBAC para el "qué puede hacer"; reglas de propiedad/contexto para el "sobre qué datos" (ej. `invoice:read` + el registro pertenece a mi sucursal/tenant).
- `[P0]` **Anti-IDOR:** nunca buscar un recurso solo por ID; filtrar por el ámbito del usuario (`WHERE id = ? AND tenant_id = ?`). Un 404 en vez de 403 cuando no se debe revelar la existencia.
- `[P0]` **Multi-tenant:** el `tenant_id` sale de la sesión autenticada, nunca de un parámetro del cliente; aplicar el filtro en una capa común (repositorio/ORM global o *row-level security* en la BD).
- `[P0]` **Mass assignment:** listas blancas de campos aceptados por DTO/esquema; el cliente nunca puede enviar `role`, `is_admin`, `tenant_id`, `status`, `owner_id`.
- `[P0]` **Escalada de privilegios:** un usuario solo puede asignar roles/permisos que él mismo posea y dentro de su ámbito; nadie edita sus propios roles; separación de funciones para acciones críticas.
- `[P1]` Acciones críticas (borrado masivo, exportación total, cambio de roles, aprobación de pagos): reautenticación + registro de auditoría + (`[P2]`) doble aprobación.
- `[P1]` Los cambios de rol/permisos aplican de inmediato o dentro de un máximo definido; invalidar caché y sesiones afectadas.
- `[P1]` Pruebas automatizadas de la **matriz rol × endpoint** (cada combinación esperada: permitido/denegado) ejecutadas en CI.
- `[P2]` Revisión periódica (trimestral) de accesos: cuentas inactivas, privilegios acumulados, cuentas de servicio.
- `[P2]` Motor de políticas declarativo (OPA, Cedar, Casbin) si las reglas crecen en complejidad.

---

## 6. Validación de entrada y salida

- `[P0]` **Consultas parametrizadas / ORM** siempre; prohibido concatenar SQL. Lo mismo para comandos del sistema, LDAP, NoSQL y plantillas.
- `[P0]` Validación en servidor con esquemas (tipo, longitud, formato, rango) por lista blanca; rechazar lo desconocido.
- `[P0]` Codificación contextual de salida (HTML, atributo, JS, URL) y plantillas con escape automático; evitar `innerHTML`/`dangerouslySetInnerHTML` con datos de usuario.
- `[P0]` **SSRF:** si el servidor descarga URLs, usar lista blanca de destinos, bloquear redes internas/metadatos de nube y no seguir redirecciones ciegamente.
- `[P1]` **Subida de archivos:** validar tipo real (no solo extensión), límite de tamaño, nombre aleatorio generado por el servidor, almacenar fuera del directorio ejecutable/público, sin ejecución, escaneo antivirus si aplica, protección contra *path traversal*.
- `[P1]` Límite de tamaño de cuerpo, paginación obligatoria y límites en consultas/exportaciones para evitar agotamiento de recursos.
- `[P1]` Deserialización segura: nunca deserializar objetos de fuentes no confiables con formatos que permitan ejecución de código.
- `[P1]` Protección de lógica de negocio: validar flujos y estados (ej. no permitir saltar pasos, doble gasto, condiciones de carrera con transacciones/bloqueos/idempotencia).

---

## 7. Seguridad web y de API

- `[P0]` **HTTPS en todo** (TLS 1.2+ recomendado 1.3), redirección HTTP→HTTPS, certificados válidos; HSTS (`max-age` ≥ 1 año, `includeSubDomains` cuando proceda).
- `[P0]` **CSRF:** cookies `SameSite` + token anti-CSRF (sincronizado o *double-submit* firmado) en toda operación que cambie estado; validar `Origin`/`Referer`. No usar `GET` para acciones que modifican datos.
- `[P0]` **CORS** restrictivo: lista blanca de orígenes explícitos; jamás `*` junto con credenciales ni reflejar el `Origin` sin validar.
- `[P1]` Cabeceras de seguridad:
  - `Content-Security-Policy` estricta (sin `unsafe-inline`; usar *nonces*/hashes), `frame-ancestors 'none'` (o lista blanca).
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy` mínima
  - `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` según el caso
  - Retirar cabeceras que expongan versión/tecnología (`Server`, `X-Powered-By`).
- `[P1]` Respuestas de autenticación/datos sensibles con `Cache-Control: no-store`.
- `[P1]` API: autenticación en todos los endpoints no públicos; versionado; límites de tasa por usuario/clave; respuestas con solo los campos necesarios (evitar sobreexposición de datos); GraphQL con límite de profundidad/costo e introspección desactivada en producción; WebSockets autenticados en el *handshake* y con autorización por mensaje.
- `[P1]` Errores de API consistentes sin detalles internos; códigos correctos (401 no autenticado, 403 sin permiso, 404 oculto, 429 limitado).
- `[P2]` Atención a *clickjacking*, *open redirect* (validar destinos de redirección con lista blanca) y *host header injection*.

---

## 8. Criptografía y secretos

- `[P0]` **Cero secretos en el repositorio** (claves, contraseñas de BD, tokens). Usar variables de entorno o un gestor (Vault, secretos de la nube, `.env` fuera de control de versiones). Activar escaneo de secretos (gitleaks/trufflehog) en pre-commit y CI.
- `[P0]` Algoritmos modernos: AES-256-GCM o ChaCha20-Poly1305 para cifrado; SHA-256+ para integridad; firmas Ed25519/ECDSA/RSA ≥ 2048 (3072 recomendado). Prohibidos DES/3DES/RC4/ECB/MD5/SHA-1 para seguridad.
- `[P0]` Aleatoriedad solo de CSPRNG del sistema (`crypto.randomBytes`, `secrets`, `SecureRandom`); nunca `Math.random()`/`rand()` para tokens.
- `[P1]` Cifrado en reposo de datos sensibles (campos o disco/volumen) y copias de seguridad cifradas; claves separadas de los datos y con rotación.
- `[P1]` Rotación de secretos documentada y ensayada; claves distintas por entorno (dev/test/prod).
- `[P1]` Conexión a la base de datos con TLS cuando salga de localhost; certificados validados (nunca desactivar verificación, ej. `verify=False`).
- `[P2]` Cifrado a nivel de campo para datos muy sensibles; HSM/KMS para claves maestras.

---

## 9. Protección de datos y privacidad

- `[P0]` **Minimización:** recolectar solo lo necesario; definir plazos de retención.
- `[P0]` Nunca registrar en logs contraseñas, tokens, números completos de tarjeta, documentos de identidad ni datos personales innecesarios; enmascarar.
- `[P1]` Clasificar datos (público, interno, confidencial, sensible) y aplicar controles según clase.
- `[P0]` Cumplir la sección **19 (marco legal de Paraguay)**: derechos del titular (acceso, rectificación, supresión, oposición, portabilidad), base legal/consentimiento registrado y notificación de incidentes en 72 h.
- `[P1]` Entornos de prueba **sin datos reales** (o anonimizados).
- `[P2]` Seudonimización de identificadores en analítica y reportes.

---

## 10. Base de datos e infraestructura

- `[P0]` Usuario de BD de la aplicación con **privilegios mínimos** (sin `DROP`, sin superusuario, sin acceso a otros esquemas); usuario separado para migraciones.
- `[P0]` BD no expuesta a internet; acceso por red privada/VPN/túnel; firewall con lista blanca.
- `[P1]` Copias de seguridad automáticas, cifradas, con restauración **probada** periódicamente y copia fuera del servidor principal.
- `[P1]` Contenedores/servicios sin ejecutar como root; imágenes mínimas; sistema operativo y dependencias con parches al día.
- `[P1]` Separación de entornos (dev/stage/prod) con credenciales independientes; modo depuración **desactivado** en producción; consolas de administración (phpMyAdmin, Adminer, paneles) no públicas.
- `[P1]` Páginas de error genéricas; sin *stack traces* ni versiones expuestas al usuario.
- `[P2]` *Row-level security* en la BD para multi-tenant; auditoría a nivel de BD de acciones privilegiadas.

---

## 11. Registro, auditoría y monitoreo (OWASP A09: Logging and Alerting Failures)

Eventos que SIEMPRE se registran, con marca de tiempo UTC, ID de usuario, IP, agente, ID de solicitud/correlación y resultado:
- Login exitoso/fallido, logout, bloqueos, cambios y recuperación de contraseña, alta/baja de MFA y passkeys, refresh de tokens reutilizados.
- **Fallos de autorización** (403) e intentos de acceso a recursos ajenos.
- Creación/edición/desactivación de usuarios, **cambios de roles y permisos** (valor anterior y nuevo, quién y cuándo).
- Acceso/exportación de datos sensibles y operaciones críticas de negocio.
- Cambios de configuración y errores de seguridad (validaciones fallidas repetidas, firmas inválidas).

Requisitos:
- `[P0]` Registro de auditoría **solo-inserción** (sin UPDATE/DELETE desde la aplicación), separado de los logs técnicos.
- `[P0]` Prevención de **inyección en logs** (sanear saltos de línea/caracteres de control) y sin datos sensibles.
- `[P1]` Logs centralizados y con retención definida; protegidos contra modificación; relojes sincronizados (NTP).
- `[P1]` **Alertas** accionables: ráfagas de fallos de login, éxito tras muchos fallos, picos de 403/429, cambios de rol fuera de horario, inicios de sesión desde ubicaciones atípicas, uso de códigos de recuperación.
- `[P2]` Panel de seguridad para administradores y plan de respuesta a incidentes (quién, qué, cómo contener, cómo notificar).

---

## 12. Manejo de errores y condiciones excepcionales (OWASP A10:2025)

- `[P0]` Todo bloque de autenticación/autorización con **ruta de error que deniega** (nunca una variable `esAdmin = true` por defecto ni un `catch` que continúa).
- `[P0]` Errores al usuario: mensajes genéricos con un ID de correlación; detalle solo en logs.
- `[P1]` Manejadores globales de excepciones; transacciones con *rollback* completo; sin estados parciales que dejen acceso abierto.
- `[P1]` Tiempos de espera, reintentos con *backoff* y *circuit breakers* en llamadas externas; límites de recursos.
- `[P2]` Pruebas de caos/fallo de componentes de seguridad (¿qué pasa si cae el servicio de MFA o el de permisos?).

---

## 13. Cadena de suministro y ciclo de desarrollo seguro (OWASP A03:2025)

- `[P0]` Dependencias con versiones fijadas (lockfile versionado); instalación reproducible (`npm ci`, `pip --require-hashes`, etc.).
- `[P1]` Escaneo automático de vulnerabilidades en dependencias (Dependabot/Renovate, `npm audit`, `pip-audit`, OWASP Dependency-Check) y SAST (Semgrep/CodeQL) en CI; el pipeline falla en severidad alta/crítica.
- `[P1]` Revisión de código obligatoria (otra persona o revisión estructurada) para cambios en autenticación, autorización y criptografía.
- `[P1]` Pipeline de build protegido: secretos del CI mínimos, artefactos verificados, nadie publica a producción sin pasar controles.
- `[P1]` Eliminar dependencias no usadas; evaluar mantenimiento y reputación antes de añadir paquetes (cuidado con *typosquatting*).
- `[P2]` SBOM, firma de artefactos/imágenes, builds reproducibles.

---

## 14. Pruebas de seguridad (qué debe existir)

1. **Unitarias/integración (CI):**
   - Matriz rol × endpoint (permitido/denegado) y casos de IDOR entre tenants/usuarios.
   - Login: respuestas genéricas, rate limiting, bloqueo temporal, rotación/invalidación de sesión al cambiar contraseña.
   - Recuperación: token expirado, reutilizado, de otro usuario.
   - JWT: `alg=none`, firma alterada, `aud` o `iss` incorrectos, token expirado.
   - Mass assignment: intento de enviar `role`/`tenant_id`.
2. **Automatizadas:** SAST, dependencias, escaneo de secretos, DAST (OWASP ZAP) contra entorno de pruebas con sus reglas de control de acceso.
3. **Manuales antes de producción (`[P1]`):** revisión de autorización de cada endpoint nuevo; prueba de fijación de sesión, CSRF, XSS, subida de archivos, enumeración de usuarios.
4. `[P2]` Pentest externo anual o ante cambios mayores; programa de divulgación responsable (`security.txt`).

---

## 15. Plan de implementación por fases (para el agente)

| Fase | Contenido | Resultado verificable |
|---|---|---|
| 1. Base | Secciones 1, 2, 8 (secretos), 10 (BD mínima), 12 | Esquema de identidad, sin secretos en repo, errores seguros |
| 2. Identidad | Secciones 3 y 4 | Registro/login/recuperación, hashing Argon2id, sesiones, MFA/passkeys |
| 3. Autorización | Sección 5 | Middleware central, RBAC + ámbito, tests matriz rol × endpoint |
| 4. Endurecimiento | Secciones 6, 7, 9 | Validación, CSRF/CORS/cabeceras, TLS, privacidad |
| 5. Observabilidad | Sección 11 | Auditoría solo-inserción y alertas |
| 6. Ciclo seguro | Secciones 13 y 14 | CI con SAST/SCA/secretos/tests de seguridad |

Al terminar cada fase: ejecutar las pruebas, actualizar el checklist y resumir lo pendiente.

---

## 16. Checklist de cierre (marcar con evidencia: archivo, test o configuración)

**Identidad**
- [ ] Contraseñas: mín. 15 (o 8 con MFA siempre), máx. ≥ 64, lista de bloqueo, sin composición ni rotación forzada
- [ ] Hash Argon2id (o alternativa justificada) con rehash en login
- [ ] Respuestas genéricas, rate limiting por IP y cuenta, bloqueo temporal con backoff
- [ ] MFA obligatorio para roles privilegiados; passkeys/TOTP; códigos de recuperación hasheados
- [ ] Recuperación con tokens de un solo uso y corta duración; revocación de sesiones al cambiar contraseña
- [ ] Sin credenciales por defecto; bootstrap seguro del primer administrador

**Sesiones y tokens**
- [ ] ID ≥ 128 bits, cookie `__Host-`/`Secure`/`HttpOnly`/`SameSite`, regeneración al login y cambio de privilegios
- [ ] Timeouts por inactividad y absoluto; logout invalida en servidor; revocación de sesiones
- [ ] JWT (si aplica): algoritmo fijado, `iss`/`aud`/`exp`/`typ` validados, refresh rotativo con detección de reutilización

**Autorización**
- [ ] Denegar por defecto; verificación central en cada solicitud en el servidor
- [ ] Permisos granulares; roles como agrupación; el código verifica permisos
- [ ] Anti-IDOR y aislamiento multi-tenant con `tenant_id` desde la sesión
- [ ] Anti mass assignment y anti-escalada (no asignar más de lo propio; último superadmin protegido)
- [ ] Reautenticación en acciones sensibles
- [ ] Tests automáticos de la matriz rol × endpoint

**Aplicación y plataforma**
- [ ] Consultas parametrizadas, validación por esquema, codificación de salida
- [ ] CSRF, CORS restrictivo, CSP y cabeceras de seguridad, HTTPS + HSTS
- [ ] Subida de archivos y SSRF controlados
- [ ] Secretos fuera del repo con escaneo; cifrado en reposo/tránsito donde corresponda
- [ ] BD con privilegios mínimos, no expuesta, backups cifrados y restauración probada
- [ ] Modo debug off en producción; errores genéricos

**Operación**
- [ ] Auditoría solo-inserción de eventos de seguridad y cambios de roles
- [ ] Logs sin datos sensibles y protegidos; alertas configuradas
- [ ] CI con SAST, dependencias, secretos y tests de seguridad; lockfiles y revisión de código
- [ ] Plan de respuesta a incidentes y proceso de parcheo documentados

---

## 17. Notas de adaptación por tipo de proyecto

- **Sistemas de escritorio con caja/POS (ej. Java + JDBC + PostgreSQL local):** aplicar igualmente las secciones 2, 3.2, 5, 10 y 11; usar `PreparedStatement`, usuario de BD con mínimos privilegios, nunca contraseñas en el código ni en archivos de configuración sin cifrar; la autorización se valida en una capa de servicio, no solo en la interfaz.
- **Apps con backend + frontend separado (SPA/móvil):** priorizar 4.2, 7 (CORS/CSP) y rate limiting por API.
- **Plataformas multi-local / SaaS:** priorizar el aislamiento por `tenant_id` (sección 5) y la auditoría por tenant.
- **Integraciones de sensores/IoT/MQTT:** autenticación por dispositivo (certificados o tokens por equipo), TLS en el broker, ACL por *topic* con mínimo privilegio, sin credenciales compartidas.
- **Herramientas de bajo código (ej. Node-RED):** proteger el editor con autenticación y MFA, no exponerlo a internet, credenciales en el almacén de secretos, y tratar los *flows* como código sujeto a revisión.

---

## 18. Instrucciones para el agente al aplicar esta plantilla

1. **No simplificar requisitos `[P0]`.** Si el stack no los permite, detenerse y reportar la alternativa antes de continuar.
2. Preferir **librerías estándar y mantenidas** del ecosistema (auth, hashing, sesiones, validación); no escribir criptografía propia.
3. Crear pruebas junto con cada característica de seguridad; no declarar un requisito cumplido sin un test o una configuración verificable.
4. Mantener un archivo `SECURITY_DECISIONS.md` en el proyecto con: decisiones tomadas, parámetros elegidos (ej. costos de Argon2id medidos), excepciones justificadas y riesgos aceptados.
5. Al final, entregar un resumen: requisitos cumplidos, parciales, no aplicables y pendientes, ordenados por prioridad.

---

## 19. Marco legal de Paraguay (cumplimiento mínimo)

> **Aviso:** resumen técnico-orientativo para el desarrollo, basado en fuentes públicas consultadas en nov. 2026. No es asesoría legal. La Ley 7593 aún espera su decreto reglamentario: revisar el texto oficial y validar con un abogado antes de producción, sobre todo en proyectos con datos sensibles, crédito o menores.

### 19.1 Normas que aplican y cuándo

| Norma | Qué regula | Estado | Aplica a |
|---|---|---|---|
| **Constitución Nacional** (art. 33 intimidad; art. 135 *habeas data*) | Base del derecho a la privacidad y a conocer/rectificar datos propios | Vigente | Todos |
| **Ley 7593/2025** de Protección de Datos Personales | Régimen general de datos de personas físicas, público y privado; crea la Agencia Nacional de Protección de Datos Personales (ANPDP, adscrita al MITIC) | Promulgada el 27-nov-2025; **exigible plenamente en nov. 2027** (24 meses) | Todos los proyectos que traten datos personales: **diseñar ya conforme a ella** |
| **Ley 6534/2020** de Datos Personales Crediticios | Datos de crédito: buros, usuarios de información crediticia, derecho al olvido (5 años), prohibido usar datos crediticios para decisiones laborales; reglamentada por el BCP (Res. 3/2023); la sanciona la SEDECO con multas de hasta 15.000 jornales mínimos (hasta 50.000 si hay reincidencia) | **Vigente hoy** (algunos artículos se derogan con la Ley 7593; esta es supletoria) | Sistemas que guardan o consultan deudas, morosidad, créditos a clientes (almacenes, cooperativas, financieras) |
| **Ley 6822/2021** Servicios de Confianza (Decr. 7576/2022) | Firma electrónica (simple y **cualificada**), sello de tiempo, documentos electrónicos; reemplazó a la Ley 4017/2010 y al término "firma digital" | Vigente (rige desde mayo 2022) | Sistemas que firman contratos, recibos, actas o documentos con valor legal |
| **Ley 4868/2013** Comercio Electrónico (Decr. 1165/2014) | Obligaciones de proveedores que venden por medios electrónicos: identificación, información clara, factura electrónica; aplica también a proveedores extranjeros que vendan a usuarios en Paraguay | Vigente | Apps de venta, delivery, marketplace, reservas con pago |
| **Código Penal** (Ley 4439/2011: arts. 146b, 146c, 146d, 174b, 175, 188) | Delitos informáticos: acceso indebido a datos y a sistemas, interceptación, sabotaje informático, fraude informático | Vigente | Alcance de pruebas de seguridad, trazabilidad y evidencia |

### 19.2 Ley 7593/2025: requisitos y su traducción técnica

Principios (art. 4): licitud, lealtad y transparencia, finalidad, minimización/proporcionalidad, exactitud, limitación del plazo de conservación, seguridad y confidencialidad, diligencia debida. Protección reforzada para **datos de niños, niñas y adolescentes** y régimen especial para **datos sensibles**.

- `[P0]` **Base legal y consentimiento:** todo tratamiento necesita base legal. Cuando se use consentimiento, debe ser libre, expreso e informado. Tabla `consents` (usuario, finalidad, texto/versión mostrada, fecha, canal, revocación). Casillas no premarcadas; revocar tan fácil como otorgar.
- `[P0]` **Aviso de privacidad** visible en registro y login: responsable, finalidades, datos recolectados, plazos de conservación, destinatarios, derechos y contacto.
- `[P0]` **Derechos del titular** (acceso, rectificación, supresión, oposición, portabilidad): funciones de administración o autoservicio que permitan **ubicar, exportar (JSON/CSV), corregir y suprimir/anonimizar** todos los datos de una persona. Plazo máximo de respuesta de **30 días** y sin costo para el titular (según resúmenes de la ley; confirmar con el texto y la reglamentación). Registrar cada solicitud y su resolución en la auditoría. La supresión debe conciliarse con obligaciones legales de conservación (ej. facturación): anonimizar en vez de borrar cuando haya que conservar el registro.
- `[P0]` **Notificación de incidentes:** avisar a la ANPDP y a los titulares afectados dentro de **72 horas** desde que se tuvo conocimiento. Requiere: runbook de respuesta a incidentes, contactos definidos, auditoría que permita determinar qué datos y a quién afectó (sección 11), y alertas que acorten el tiempo de detección.
- `[P0]` **Seguridad y confidencialidad:** medidas técnicas y organizativas adecuadas = esta plantilla completa (secciones 3 a 13). Acceso a datos personales solo por necesidad de la función (mínimo privilegio, sección 5).
- `[P1]` **Minimización y retención:** inventario de datos por tabla (finalidad, base legal, plazo); tareas programadas que borren o anonimicen al vencer el plazo; no pedir datos "por si acaso".
- `[P1]` **Datos sensibles y de menores:** cifrado a nivel de campo, acceso restringido y auditado; para menores, verificar el consentimiento del representante y evitar perfilado.
- `[P1]` **Transferencias internacionales:** si la base de datos, backups o servicios (nube, correo, analítica, IA) están fuera de Paraguay, solo a países con protección adecuada o con garantías (cláusulas contractuales). Documentar la ubicación de cada proveedor en `SECURITY_DECISIONS.md`.
- `[P1]` **Encargados de tratamiento (proveedores):** contrato que fije finalidad, seguridad y confidencialidad; lista de subencargados.
- `[P1]` **Oficial de protección de datos (DPO):** la ley prevé que los sujetos obligados cuenten con uno; el decreto reglamentario precisará quiénes. Dejar un campo/canal de contacto de privacidad en el sistema.
- `[P1]` **Registro de actividades de tratamiento** (qué datos, para qué, quién accede, dónde están); base para auditorías de la ANPDP.
- `[P2]` Evaluaciones de impacto en protección de datos para tratamientos de alto riesgo (biometría, perfilado, grandes volúmenes).

**Entregables técnicos mínimos por proyecto:** (1) esquema de consentimientos, (2) endpoint/pantalla de derechos del titular, (3) exportación y anonimización de un titular, (4) política de retención automatizada, (5) runbook de incidentes de 72 h, (6) inventario de datos y de proveedores.

### 19.3 Ley 6534/2020 (datos crediticios) — si el sistema maneja crédito o morosidad
- `[P0]` Usar datos crediticios solo para la finalidad permitida (evaluación crediticia); **prohibido** emplearlos o cederlos para decisiones laborales (art. 15).
- `[P0]` Acceso a información crediticia restringido por rol y registrado en auditoría (quién consultó a quién y para qué).
- `[P1]` Cumplir el plazo máximo de **5 años** de publicación/conservación de datos adversos y permitir al titular acceso, actualización, rectificación y supresión.
- `[P1]` No actuar como buró de información crediticia sin la autorización del BCP.

### 19.4 Ley 6822/2021 (firma y documentos electrónicos)
- `[P1]` Distinguir **firma electrónica** (válida, pero su fuerza probatoria se evalúa) de **firma electrónica cualificada** (equivale a la manuscrita; solo la emiten Prestadores Cualificados de Servicios de Confianza habilitados por el MIC). No llamarla "firma digital" en la interfaz ni en la documentación.
- `[P1]` Si el sistema genera contratos, actas o recibos con efecto legal: guardar el documento íntegro, hash (SHA-256), sello de tiempo, identidad del firmante y evidencia de aceptación; impedir la modificación posterior (versionado o inmutabilidad).
- `[P2]` Integración con firma electrónica cualificada de un prestador habilitado cuando el cliente lo requiera.

### 19.5 Ley 4868/2013 (comercio electrónico) — módulos de venta, delivery y reservas
- `[P1]` Mostrar identificación del proveedor (razón social, RUC, domicilio, contacto), precios con impuestos, condiciones de contratación, entrega y devoluciones antes de que el usuario pague.
- `[P1]` Conservar la evidencia de la contratación (aceptación de términos con fecha/versión) y emitir comprobante/factura electrónica conforme a la normativa tributaria vigente (verificar requisitos actuales de la DNIT/SIFEN con el contador del cliente).
- `[P1]` Canal de reclamos accesible y datos de pago tratados solo por pasarelas autorizadas (no guardar PAN/CVV; ver PCI DSS si hay tarjetas).

### 19.6 Código Penal (delitos informáticos)
- `[P1]` Toda prueba de seguridad (pentest, escaneos) con **autorización escrita** del titular del sistema y alcance definido; sin ella puede constituir acceso indebido (arts. 146b, 174b).
- `[P1]` Mantener la auditoría con integridad (sección 11) para que sirva de evidencia ante denuncias y para demostrar diligencia.
- `[P1]` Reservar y proteger las credenciales de terceros: no almacenar ni difundir claves de acceso ajenas (art. 146d sanciona preparar/difundir medios para el acceso indebido).

### 19.7 Checklist legal Paraguay
- [ ] Inventario de datos personales con finalidad, base legal y plazo de conservación
- [ ] Aviso de privacidad y registro de consentimientos versionado
- [ ] Funciones de acceso, rectificación, supresión, oposición y portabilidad (respuesta ≤ 30 días)
- [ ] Runbook y alertas para notificar incidentes en ≤ 72 h
- [ ] Datos sensibles/menores con protección reforzada
- [ ] Ubicación de datos y proveedores documentada; garantías para transferencias internacionales
- [ ] Contratos con encargados; contacto de privacidad/DPO definido
- [ ] Si hay crédito/morosidad: control de finalidad, auditoría de consultas, retención ≤ 5 años (Ley 6534)
- [ ] Si hay firmas/contratos: evidencia de integridad y sello de tiempo (Ley 6822)
- [ ] Si hay ventas online: información al consumidor y comprobante electrónico (Ley 4868 + normativa DNIT)
- [ ] Pruebas de seguridad con autorización escrita
- [ ] Revisión legal confirmada por un abogado y fecha de próxima revisión (al publicarse el decreto reglamentario de la Ley 7593)

**Pendiente de verificar con asesoría legal** (no confirmado en esta investigación): decreto reglamentario y régimen exacto de sanciones de la Ley 7593; quiénes deben designar DPO; obligaciones concretas de facturación electrónica (SIFEN/DNIT) y de defensa del consumidor para cada tipo de negocio.

---

## 20. Datos por entidad, logs y políticas operativas

> Los campos y plazos de esta sección son **recomendaciones de diseño** (minimización primero). Los plazos de conservación con efecto legal o tributario deben confirmarse con el contador/abogado del cliente.

### 20.1 Datos que debe tener cada entidad (modelo mínimo genérico)

**Campos comunes en todas las tablas de negocio** `[P0]`: `id` (UUID/ULID), `tenant_id` (comercio dueño del dato), `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at` (borrado lógico), `version` (control de concurrencia). Fechas en UTC; mostrar en `America/Asuncion`.

**Comercio / Negocio (tenant)** — quien contrata el sistema
| Grupo | Campos |
|---|---|
| Identidad | razón social, nombre de fantasía, RUC (con dígito verificador), tipo de contribuyente |
| Ubicación y contacto | dirección, ciudad/departamento, teléfono, email de contacto, responsable/representante |
| Fiscal | datos de facturación exigidos por la normativa tributaria vigente (timbrado o datos de facturación electrónica según corresponda; confirmar con el contador) |
| Estructura | locales/sucursales, cajas o puntos de venta, depósitos |
| Operación | moneda (PYG, importes **enteros** en guaraníes; para otras monedas usar enteros en la unidad mínima), zona horaria, plan/licencia, estado (activo, suspendido) |
| Privacidad | contacto/responsable de protección de datos, versión de política aceptada |
| No guardar | claves de acceso de terceros, credenciales de otros sistemas en claro |

**Usuario (cuenta de acceso al sistema)** — empleados/operadores del comercio
| Grupo | Campos |
|---|---|
| Identidad | nombre y apellido, email (único), teléfono (opcional, para recuperación/alertas) |
| Acceso | `password_hash`, estado (pendiente/activo/bloqueado/desactivado), `mfa_enabled`, passkeys, último login, intentos fallidos, `locked_until` |
| Autorización | roles y permisos por comercio/local; fecha de alta y quien la aprobó |
| Preferencias | idioma, zona horaria |
| Ciclo de vida | `created_by`, `deactivated_at`, motivo de baja (auditable) |
| Solo si hace falta | número de documento (CI) en un campo cifrado; no pedirlo "por si acaso" |

**Cliente (persona o empresa que compra o recibe el servicio)** — dato personal protegido por la Ley 7593
| Grupo | Campos |
|---|---|
| Identidad | tipo (persona física/jurídica), nombre o razón social, documento (CI o RUC) |
| Contacto | teléfono, email, dirección de entrega/facturación (solo si el negocio lo necesita) |
| Comercial | categoría, condición de pago, observaciones internas (sin datos sensibles) |
| Crédito (si aplica) | límite, saldo, historial de pagos → regido por Ley 6534; acceso restringido y auditado |
| Privacidad | consentimientos vigentes (finalidad, fecha, versión, canal), preferencias de contacto, fecha de solicitud de derechos |
| Evitar salvo necesidad legal | fecha de nacimiento exacta, datos de salud, biométricos, afiliación política/religiosa (datos sensibles → cifrado de campo y base legal expresa) |

**Transacción / Comprobante** — ventas, pagos, reservas, pedidos
`id`, `tenant_id`, local/caja, usuario que la registró, cliente (o consumidor final), fecha-hora UTC, ítems con precio e impuestos **congelados** al momento de la operación, totales, medio de pago, estado (borrador/confirmada/anulada), **motivo y autor de la anulación** (nunca borrar), número de comprobante, referencia fiscal, hash de integridad. Datos de tarjeta: **no guardar** número completo ni CVV (usar pasarela autorizada y guardar solo token y últimos 4 dígitos).

**Reglas para los datos** `[P1]`
- Cada campo con **finalidad, base legal y plazo** (inventario de datos, sección 19.2).
- Los datos **sensibles** en tabla/columna aparte con cifrado y acceso restringido.
- Registros contables/fiscales: **anular, no borrar**; el borrado de datos personales se resuelve anonimizando el titular y conservando el registro agregado.
- Unicidad y validación de formato (RUC con dígito verificador, email, teléfono) en servidor y en BD (constraints).

### 20.2 Logs que debe tener el sistema

**Formato** `[P0]`: JSON estructurado, un evento por línea, con: `timestamp` (UTC, ISO 8601), `level`, `event` (código estable, ej. `auth.login.failed`), `service`/`env`, `tenant_id`, `user_id`, `actor_type` (usuario/sistema/API), `ip`, `user_agent`, `request_id` (correlación), `resource`, `action`, `result` (ok/denegado/error), `reason`. **Nunca** registrar contraseñas, tokens, secretos, CVV/PAN, ni cuerpos completos de solicitudes con datos personales; enmascarar (ej. `***1234`).

| Tipo de log | Qué registra | Retención sugerida | Notas |
|---|---|---|---|
| **Auditoría de seguridad** | login/logout, fallos, MFA, cambios y recuperación de contraseña, bloqueos, cambios de roles y permisos, altas/bajas de usuarios, fallos de autorización | 12 meses en línea + archivo hasta 5 años | Solo-inserción, protegido contra alteración (sección 11) |
| **Auditoría de negocio** | creación, modificación (valor anterior → nuevo), anulación y eliminación de ventas, precios, stock, caja, cierres, descuentos manuales, aprobaciones | según plazo legal/tributario (confirmar) | Quién, cuándo, qué cambió, por qué |
| **Acceso a datos personales/sensibles** | consultas y exportaciones de clientes, datos de crédito, exportaciones masivas, solicitudes de derechos del titular y su resolución | 12–24 meses | Evidencia ante ANPDP y Ley 6534 |
| **Aplicación (técnico)** | errores, excepciones, advertencias, trabajos programados, integraciones fallidas, tiempos lentos | 30–90 días | Sin datos personales; con `request_id` |
| **Acceso HTTP/API** | método, ruta, código de estado, latencia, IP, usuario, tamaño | 90 días | Base para detectar abuso y rate limiting |
| **Base de datos** | consultas lentas, errores, conexiones fallidas, cambios de esquema/migraciones, accesos de cuentas privilegiadas | 30–90 días (cambios de esquema: permanente) | Auditar `GRANT`, `DROP`, usuarios nuevos |
| **Infraestructura/sistema** | accesos SSH/RDP, `sudo`, cambios de firewall, reinicios, parches, resultados de backups | 12 meses | Centralizar fuera del servidor |
| **Integraciones** | llamadas a pasarelas de pago, facturación electrónica, correo/SMS, con estado y referencia | 12 meses | Sin credenciales |

Requisitos: `[P0]` relojes sincronizados (NTP) · `[P1]` logs enviados a un almacén **separado** del servidor de la aplicación (que la app no pueda borrar) · `[P1]` alertas sobre: ráfagas de login fallido, éxito tras muchos fallos, picos de 403/429/500, cambios de rol fuera de horario, exportaciones masivas, borrados/anulaciones anómalos, fallo de backup · `[P1]` rotación y compresión de logs · `[P2]` cadena de hashes o almacenamiento WORM para auditoría crítica.

### 20.3 Política de respaldo y recuperación de base de datos

1. `[P0]` **Definir RPO y RTO por proyecto** y escribirlos en `SECURITY_DECISIONS.md`. Referencia: sistemas transaccionales con dinero → RPO ≤ 15 min (copia continua de WAL/binlog) y RTO ≤ 4 h; sistemas internos de menor criticidad → RPO ≤ 24 h y RTO ≤ 24 h.
2. `[P0]` **Regla 3-2-1-1-0:** 3 copias de los datos, en 2 medios distintos, 1 copia fuera del sitio (otra ubicación física/nube), 1 copia **inmutable u offline** (a salvo de ransomware) y 0 errores en la verificación de restauración.
3. `[P0]` **Tipos de copia:** completa periódica (diaria o semanal) + incrementales/diferenciales + **archivado continuo de transacciones para recuperación a un punto en el tiempo (PITR)**: en PostgreSQL, base backup + archivado de WAL con herramientas como pgBackRest o WAL-G; en MySQL/MariaDB, copia física + binlog. Complementar con volcado lógico (`pg_dump`/`mysqldump`) para portabilidad entre versiones.
4. `[P0]` **Cifrado** de todas las copias (en tránsito y en reposo, AES-256) con claves **separadas** del servidor y respaldadas por separado (si se pierde la clave, la copia no sirve).
5. `[P0]` **Aislamiento de credenciales:** el trabajo de backup usa un usuario con privilegios mínimos de lectura; el destino acepta solo escritura/anexado desde el servidor de producción (que un atacante en producción no pueda borrar las copias).
6. `[P0]` **Pruebas de restauración:** restauración automática **mensual** en un entorno aislado con verificación (checksums, conteo de filas, consultas de humo, integridad de tablas críticas) y **simulacro de recuperación completa** al menos cada 6 meses, midiendo el RTO real y documentando el resultado. Un backup sin restauración probada no cuenta como backup.
7. `[P1]` **Retención (GFS) sugerida:** diarias 14 días · semanales 8 semanas · mensuales 12 meses · anual según obligación legal. Ajustar a los plazos tributarios/contractuales.
8. `[P1]` **Monitoreo:** alerta inmediata si falla o no corre un backup, si el tamaño varía de forma anómala o si crece el retraso del archivado de WAL; registro de cada ejecución en logs de infraestructura.
9. `[P1]` **Privacidad y backups:** la supresión de datos personales se aplica en producción de inmediato y en los backups **al vencer su rotación**; mantener una **lista de supresiones** que se reaplique tras cada restauración. Documentar este tratamiento en la política de retención (Ley 7593).
10. `[P1]` **Ubicación:** si las copias fuera del sitio están en el extranjero, aplica la regla de transferencias internacionales (sección 19.2).
11. `[P1]` **Qué más respaldar:** archivos subidos por usuarios, configuración, secretos (en gestor de secretos con copia propia), infraestructura como código, scripts de despliegue y esquema/migraciones; el código vive en un repositorio remoto.
12. `[P1]` **Runbook de recuperación** escrito (quién decide, pasos, orden de restauración, contactos, verificación y comunicación a clientes), accesible **sin depender del sistema caído**.
13. `[P2]` Réplica en caliente o *standby* para alta disponibilidad (no reemplaza al backup: un borrado erróneo se replica).
- **Sistemas locales (POS/caja con servidor PostgreSQL en el local):** backup automático diario a otro disco/equipo del local + copia cifrada fuera del local, UPS contra cortes, y prueba de restauración trimestral.

### 20.4 Otras políticas mínimas que debe tener cada proyecto

| Política | Contenido mínimo |
|---|---|
| **Gestión de accesos** | alta/baja de usuarios (offboarding el mismo día), revisión trimestral de roles, cuentas de servicio inventariadas, acceso administrativo solo con MFA |
| **Gestión de cambios** | cambios por *pull request* con revisión; migraciones versionadas y reversibles; despliegues con plan de *rollback*; ventana de mantenimiento |
| **Parcheo y vulnerabilidades** | críticas ≤ 7 días, altas ≤ 30 días (valores sugeridos); inventario de componentes (SBOM opcional) |
| **Retención y eliminación** | plazo por tipo de dato, borrado/anonimización automática, constancia de ejecución |
| **Respuesta a incidentes** | roles, clasificación de severidad, contención, evidencia, comunicación, notificación en 72 h a la ANPDP y a los titulares (Ley 7593), lecciones aprendidas |
| **Continuidad (DR)** | RPO/RTO, sitio alterno o plan de recuperación, contactos, pruebas periódicas |
| **Clasificación de datos** | público, interno, confidencial, sensible, con controles por clase |
| **Proveedores** | lista, contrato con cláusulas de seguridad/confidencialidad, ubicación de los datos |
| **Entornos y datos de prueba** | separación dev/stage/prod; datos de prueba anonimizados o sintéticos |
| **Capacitación** | inducción de seguridad y privacidad al personal que usa el sistema |

### 20.5 Checklist de datos, logs y respaldos
- [ ] Modelo de datos con campos comunes (`tenant_id`, auditoría, borrado lógico) y datos mínimos por entidad
- [ ] Datos sensibles separados y cifrados; anulaciones en lugar de borrados en registros fiscales
- [ ] Logs estructurados con `request_id`, sin datos sensibles, por tipo y con retención definida
- [ ] Logs en almacén separado, con alertas configuradas
- [ ] RPO/RTO definidos y escritos
- [ ] Backups 3-2-1-1-0 cifrados, con PITR y copia inmutable/offline
- [ ] Restauración probada mensualmente y simulacro semestral documentado
- [ ] Alerta de fallo de backup; lista de supresiones aplicable al restaurar
- [ ] Runbook de recuperación y de incidentes accesible fuera del sistema
- [ ] Políticas de accesos, cambios, parcheo, retención y proveedores documentadas

---

*Versión de la plantilla: 1.2 (incluye marco legal de Paraguay, modelo de datos, logs y respaldos) · noviembre de 2026. Revisar al menos una vez al año o cuando cambien OWASP ASVS, OWASP Top 10, NIST SP 800-63, o se publique la reglamentación de la Ley 7593.*
