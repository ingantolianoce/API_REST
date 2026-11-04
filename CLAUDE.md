# {{PROJECT_NAME}} — instrucciones para el agente

Stack: Java 21 · Spring Boot 4 · Spring Security 7 · PostgreSQL (Flyway) · Vue 3 + TypeScript. Paquete: `{{PACKAGE}}`.
Este proyecto nació de la plantilla de seguridad (ver `.template/VERSION`). Su diseño de seguridad es **obligatorio**.

@docs/security/CLAUDE_SEGURIDAD.md

## Cómo trabajar aquí (reglas operativas del stack)

- **Nunca debilitar un requisito P0.** Si algo lo impide, detenerse y reportar la alternativa antes de continuar.
- Mapa requisito → implementación → prueba: `docs/security/STACK_SPRING_VUE.md`. Estado: `docs/security/ESTADO_CHECKLIST.md`.
- Referencia completa (solo si hace falta detalle): `docs/security/SEGURIDAD_USUARIOS_ROLES.md`.
- Los archivos listados en `.template/managed-files.txt` **no se editan** (los sobrescribe `scripts/template-sync.sh`);
  proponer el cambio a la plantilla y documentar la excepción en `SECURITY_DECISIONS.md`.

### Al agregar un endpoint
1. `@PreAuthorize("hasAuthority('recurso:accion')")` (permiso, nunca `hasRole`); `permitAll()` solo si es público y explícito.
   Si falta, `ArchitectureTest` falla.
2. DTO de entrada como `record` con validación; **nunca** `tenantId`, `status`, `role`, `isAdmin` ni `ownerId` (hay `fail-on-unknown-properties`).
3. El tenant y el actor salen del `@AuthenticationPrincipal AppUserDetails`; toda consulta filtra por `tenant_id`
   (`WHERE id = ? AND tenant_id = ?`); recurso ajeno ⇒ **404**.
4. Consultas con `JdbcClient` y parámetros con nombre; jamás concatenar SQL.
5. Auditar los cambios (`AuditService`, valor anterior y nuevo) en la **misma transacción**; sin datos sensibles en `details`.
6. Tests: permitido / denegado (matriz rol × endpoint) / IDOR entre tenants / validación. Ver `AuthorizationIT`.

### Al agregar un permiso o rol
Nueva migración Flyway **versionada** (`V3__...sql`); nunca editar `V1`/`V2` ya aplicadas. El código verifica permisos `recurso:accion`.

### Al agregar tablas
Campos comunes (`id uuid`, `tenant_id`, `created_at/by`, `updated_at/by`, `deleted_at`, `version`), importes enteros, fechas UTC;
registros fiscales se **anulan**, no se borran; datos personales ⇒ actualizar `docs/privacy/INVENTARIO_DATOS.md`.
Dar al usuario `app_runtime` solo los privilegios necesarios en `R__grants.sql`.

### Antes de dar algo por terminado
`cd backend && mvn verify` (necesita `docker compose up -d db`) · `cd frontend && npm test && npm run build` ·
revisar la Definición de terminado de `CLAUDE_SEGURIDAD.md` · anotar decisiones en `SECURITY_DECISIONS.md`.

### Comandos
```bash
docker compose up -d db                     # PostgreSQL local (roles de mínimo privilegio)
cd backend && mvn verify                    # pruebas (unitarias + integración + arquitectura)
cd frontend && npm ci && npm test && npm run build
scripts/template-sync.sh --check            # ¿hay una versión nueva de la plantilla de seguridad?
```
