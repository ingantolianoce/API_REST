# Plantilla de seguridad — Java Spring Boot · PostgreSQL · Vue

Base para **iniciar todos los proyectos nuevos** con el mismo diseño de seguridad: documentación normativa
(OWASP ASVS 5.0, Top 10:2025, NIST SP 800-63B Rev. 4, marco legal de Paraguay), un esqueleto ejecutable que ya
implementa los controles de identidad/autorización y las **pruebas que los verifican**, CI con escáneres, y un
mecanismo para **mantenerla actualizada** y propagar los cambios a los proyectos.

> Versión de la plantilla: ver [`.template/VERSION`](.template/VERSION) · Historial: [`CHANGELOG.md`](CHANGELOG.md)

## Crear un proyecto nuevo

1. En GitHub: **Use this template → Create a new repository** (o clonar y desvincular el historial).
   *(Pendiente una sola vez: marcar este repositorio como "Template repository" en Settings → General.)*
2. Dentro del repositorio nuevo:
   ```bash
   scripts/new-project.sh almacen-pos py.com.miempresa.almacen "Almacén POS"
   ```
   Renombra el paquete Java y los artefactos, rellena `SECURITY_DECISIONS.md` y elimina lo exclusivo de la plantilla.
3. Levantar y verificar:
   ```bash
   cp .env.example .env            # completar secretos: openssl rand -base64 24  /  openssl rand -base64 32
   docker compose up -d db
   (cd backend && mvn verify)      # 56 pruebas: unitarias, integración (PostgreSQL real) y arquitectura
   (cd frontend && npm ci && npm test && npm run build)
   ```
4. Primer administrador (sin credenciales por defecto): ver [`docs/security/STACK_SPRING_VUE.md`](docs/security/STACK_SPRING_VUE.md#bootstrap-del-primer-superadmin).
5. Completar la **Ficha del proyecto** de [`SECURITY_DECISIONS.md`](SECURITY_DECISIONS.md) y el [inventario de datos](docs/privacy/INVENTARIO_DATOS.md).

## Qué incluye

| Carpeta / archivo | Contenido |
|---|---|
| [`docs/security/SEGURIDAD_USUARIOS_ROLES.md`](docs/security/SEGURIDAD_USUARIOS_ROLES.md) | Especificación completa (referencia normativa; incluye marco legal de Paraguay) |
| [`docs/security/CLAUDE_SEGURIDAD.md`](docs/security/CLAUDE_SEGURIDAD.md) | Versión compacta; la importa `CLAUDE.md` para que el agente la aplique siempre |
| [`docs/security/STACK_SPRING_VUE.md`](docs/security/STACK_SPRING_VUE.md) | Cada requisito → cómo y dónde está implementado en este stack (con la prueba que lo verifica) |
| [`docs/security/ESTADO_CHECKLIST.md`](docs/security/ESTADO_CHECKLIST.md) | Checklist de cierre con evidencia: qué está hecho, parcial y pendiente |
| [`docs/security/CICLO_DE_ACTUALIZACION.md`](docs/security/CICLO_DE_ACTUALIZACION.md) | Cómo y cuándo se actualiza la plantilla y cómo llegan los cambios a los proyectos |
| [`docs/operations/`](docs/operations) | Runbooks de incidentes (72 h) y recuperación; política de respaldos |
| [`docs/privacy/INVENTARIO_DATOS.md`](docs/privacy/INVENTARIO_DATOS.md) | Inventario de datos personales (Ley 7593) |
| [`backend/`](backend) | Spring Boot 4 · Security 7 · Flyway · PostgreSQL · Argon2id · MFA TOTP · auditoría solo-inserción |
| [`frontend/`](frontend) | Vue 3 + TypeScript + Pinia: login, MFA, cambio de clave, CSRF, sin tokens en el navegador |
| [`db/`](db) | Roles de BD de mínimo privilegio (migrador / aplicación) |
| [`.github/`](.github) | CI, SAST (CodeQL), secretos (gitleaks), dependencias, Dependabot, avisos de actualización |
| [`scripts/`](scripts) | `new-project.sh` (inicializar) · `template-sync.sh` (actualizar) |

## Mantener la plantilla al día

* **Trimestral** (ene/abr/jul/oct) un workflow abre un issue con el checklist de revisión; además hay disparadores por
  evento (nueva versión de ASVS/NIST, decreto de la Ley 7593, CVE crítico).
* Cada cambio sube la versión (`SemVer`) y se anota en el `CHANGELOG.md` separando **Documentos/CI** (se sincronizan solos)
  de **Código base** (se aplican a mano).
* Los **proyectos** reciben un issue semanal automático si su versión quedó atrás y actualizan con
  `scripts/template-sync.sh`.

Detalle completo: [`docs/security/CICLO_DE_ACTUALIZACION.md`](docs/security/CICLO_DE_ACTUALIZACION.md).

## Reglas de oro (resumen)

Denegar por defecto · autorizar siempre en el servidor y con **permisos** (no nombres de rol) · `tenant_id` de la sesión,
nunca del cliente · sin secretos en el repo · sin credenciales por defecto · fallar cerrado · cada requisito P0 con su
prueba. Un endpoint sin `@PreAuthorize` **rompe el build** (`ArchitectureTest`).

> No es asesoría legal. Validar el marco legal con un abogado y revisar al publicarse el decreto de la Ley 7593.
