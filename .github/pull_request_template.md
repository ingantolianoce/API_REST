## Qué cambia y por qué

## Checklist de seguridad (Definición de terminado)
- [ ] Requisitos P0 aplicables cumplidos **y probados** (tests de seguridad incluidos)
- [ ] Sin secretos ni datos personales en código, logs ni repositorio
- [ ] Cada endpoint nuevo: `@PreAuthorize` con permiso, y tests permitido / denegado / IDOR (otro tenant)
- [ ] DTOs de entrada con lista blanca (nada de `tenantId`, `status`, `role` desde el cliente)
- [ ] Dependencias escaneadas, sin vulnerabilidades críticas
- [ ] Decisiones, parámetros y excepciones anotados en `SECURITY_DECISIONS.md`
- [ ] Cambios en datos personales reflejados en `docs/privacy/INVENTARIO_DATOS.md`
- [ ] Si toca auth/authz/cripto: revisión de otra persona
