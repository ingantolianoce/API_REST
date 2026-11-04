-- Roles de base de datos (principio de minimo privilegio, seccion 10 de la plantilla).
-- Se ejecuta UNA vez como superusuario al crear la BD (db/init/01-roles.sh en docker compose, o a mano).
-- Las contrasenas llegan por variables de psql (-v), NUNCA van en el repositorio:
--   psql -d app -v migrator_pw="$DB_MIGRATOR_PASSWORD" -v runtime_pw="$DB_RUNTIME_PASSWORD" -f db/roles.sql
--
--  app_migrator : dueno del esquema; lo usa SOLO Flyway (DDL).
--  app_runtime  : lo usa la aplicacion; sin DDL, sin DROP, sin superusuario; sin UPDATE/DELETE
--                 sobre audit_log (ver R__grants.sql).

\if :{?migrator_pw}
\else
  \echo 'Falta -v migrator_pw=... y -v runtime_pw=...'
  \quit
\endif

CREATE ROLE app_migrator LOGIN PASSWORD :'migrator_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE app_runtime  LOGIN PASSWORD :'runtime_pw'  NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- La BD y el esquema public pertenecen al migrador; el runtime solo puede usarlos (sin DDL).
ALTER DATABASE :"DBNAME" OWNER TO app_migrator;
ALTER SCHEMA public OWNER TO app_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_runtime;
GRANT CREATE, USAGE ON SCHEMA public TO app_migrator;
