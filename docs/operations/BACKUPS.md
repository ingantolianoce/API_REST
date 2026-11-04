# Política de respaldo y recuperación de la base de datos (plantilla)

Basada en la sección 20.3 de `SEGURIDAD_USUARIOS_ROLES.md`. **La base no implementa backups**: cada proyecto los configura y prueba (✅ cuando haya evidencia).

## Parámetros (completar y copiar a `SECURITY_DECISIONS.md`)
| Parámetro | Valor |
|---|---|
| RPO (con dinero ≤ 15 min; interno ≤ 24 h) | |
| RTO (con dinero ≤ 4 h; interno ≤ 24 h) | |
| Ubicación copia externa (país/proveedor) | |
| Retención GFS (14 diarias · 8 semanales · 12 mensuales · anual legal) | |

## Regla 3-2-1-1-0
3 copias · 2 medios · 1 externa · 1 **inmutable u offline** (a salvo de ransomware) · 0 errores de restauración.

## Implementación sugerida (PostgreSQL)
* Completa semanal/diaria + incrementales + **archivado continuo de WAL (PITR)** con **pgBackRest** o **WAL-G**; volcado lógico (`pg_dump`) complementario.
* **Cifrado AES-256** en reposo y tránsito; clave **separada** del servidor y respaldada por separado.
* Usuario de backup con mínimos privilegios; el repositorio de copias acepta solo anexar desde producción (producción no puede borrarlas).
* Ejemplo `pgbackrest.conf` (ajustar):
  ```ini
  [global]
  repo1-type=s3                       # o posix/sftp; con object-lock/versionado inmutable
  repo1-cipher-type=aes-256-cbc       # la clave en el gestor de secretos, no en este archivo
  repo1-retention-full=8
  start-fast=y
  [app]
  pg1-path=/var/lib/postgresql/17/main
  ```
  ```conf
  # postgresql.conf
  archive_mode = on
  archive_command = 'pgbackrest --stanza=app archive-push %p'
  ```

## Pruebas (un backup sin restauración probada no cuenta)
* **Mensual**: restauración automática en un entorno aislado + verificación (checksums, conteo de filas, consultas de humo, integridad de `audit_log`).
* **Cada 6 meses**: simulacro completo de recuperación midiendo el **RTO real**; documentar el resultado.
* Alerta inmediata si un backup falla, no corre, cambia anómalamente de tamaño o el archivado de WAL se atrasa.

## Privacidad
La supresión se aplica en producción de inmediato y en los backups al vencer su rotación; mantener la **lista de supresiones** y reaplicarla tras cada restauración.
Qué más respaldar: archivos subidos, configuración, secretos (en gestor con copia propia), IaC, scripts de despliegue, esquema/migraciones.

## POS / sistemas locales
Backup diario a otro disco/equipo del local + copia cifrada fuera del local, UPS, prueba de restauración trimestral.
