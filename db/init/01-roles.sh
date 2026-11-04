#!/bin/sh
# Se ejecuta automaticamente por la imagen oficial de PostgreSQL al crear el volumen por primera vez.
# Crea los roles app_migrator / app_runtime con las contrasenas del entorno (nunca fijas en el repositorio).
set -eu
psql -v ON_ERROR_STOP=1 \
     -v migrator_pw="$DB_MIGRATOR_PASSWORD" -v runtime_pw="$DB_RUNTIME_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /roles.sql
