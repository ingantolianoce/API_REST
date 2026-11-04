# Runbook de recuperación ante desastres (plantilla)

> Guardar **fuera del sistema** que protege. Completar y ensayar (simulacro completo cada 6 meses, midiendo el RTO real).

**RPO objetivo:** ____ min · **RTO objetivo:** ____ h · **Decide la recuperación:** ________

## Antes de empezar
1. ¿Es un incidente de seguridad? Si hay sospecha de intrusión, seguir primero `RUNBOOK_INCIDENTES.md` (no restaurar sobre un entorno comprometido).
2. Identificar el punto en el tiempo deseado (PITR) y el destino (nuevo servidor limpio).

## Orden de restauración
1. Infraestructura base (red privada, firewall, host sin root, TLS).
2. Secretos desde el gestor (`APP_CRYPTO_KEY`, contraseñas de roles de BD) — **si se pierde la clave de cifrado, los backups cifrados no sirven**.
3. PostgreSQL: restaurar backup base + archivos WAL hasta el punto elegido (pgBackRest/WAL-G, ver `BACKUPS.md`).
4. Crear/verificar roles `app_migrator` / `app_runtime` (`db/roles.sql`), correr migraciones (Flyway) y los grants repetibles.
5. **Reaplicar la lista de supresiones** de datos personales (derecho de supresión, Ley 7593).
6. Backend → frontend; humo: login de prueba, `GET /actuator/health`, conteos de filas de tablas críticas, `audit_log` consistente.
7. Revocar sesiones previas si hubo incidente (`TRUNCATE`-equivalente solo sobre `spring_session*`, con el usuario migrador).
8. Comunicar a clientes; registrar RTO real y desviaciones; actualizar este runbook.

## Contactos
| Qué | Quién | Contacto |
|---|---|---|
| Proveedor de hosting | | |
| DBA / responsable | | |
| Custodio de claves (copia de `APP_CRYPTO_KEY`) | | |
