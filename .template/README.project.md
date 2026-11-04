# {{PROJECT_NAME}}

Proyecto creado desde la plantilla de seguridad (Java Spring Boot · PostgreSQL · Vue). El diseño de seguridad es obligatorio:
ver [`CLAUDE.md`](CLAUDE.md), [`SECURITY_DECISIONS.md`](SECURITY_DECISIONS.md) y [`docs/security/`](docs/security).

## Desarrollo local

```bash
cp .env.example .env                 # completar secretos (openssl rand -base64 24 / 32)
docker compose up -d db
cd backend && mvn verify             # pruebas con PostgreSQL real
cd backend && mvn spring-boot:run    # API en :8080
cd frontend && npm ci && npm run dev # SPA en :5173 (proxy a /api)
```

Las cookies `__Host-` exigen `Secure`: use Chrome/Firefox en `http://localhost` (tratado como seguro) o HTTPS local.

## Primer administrador

Active el bootstrap una sola vez (`APP_BOOTSTRAP_*` en `.env`), arranque el backend, lea la clave de un solo uso en
`.local/bootstrap/admin-credentials.txt`, **bórrela** y vuelva a desactivar el bootstrap. El primer ingreso fuerza cambio de clave y alta de MFA.

## Mantenimiento

* `scripts/template-sync.sh --check` · ¿hay una versión nueva de la plantilla de seguridad? (también avisa un issue semanal)
* Revisión trimestral: `docs/security/CICLO_DE_ACTUALIZACION.md`
