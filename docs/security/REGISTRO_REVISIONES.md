# Registro de revisiones de la plantilla

| Fecha | Versión resultante | Responsable | Fuentes verificadas | Cambios / hallazgos |
|---|---|---|---|---|
| 2026-11-04 | 1.0.0 | *(completar)* | OWASP ASVS 5.0, Top 10:2025, NIST SP 800-63B Rev. 4, RFC 8725, marco legal PY (según `SEGURIDAD_USUARIOS_ROLES.md` v1.2) | Versión inicial: documentos + esqueleto Spring Boot/PostgreSQL/Vue con 56+6 pruebas. Hallazgos al construirla: Spring Session no aplicaba las propiedades de cookie (ahora explícitas en `SessionConfig`); UUID de sesión por defecto = 122 bits (ahora 256 bits); `csrf()` de spring-security-test contamina el contexto compartido (pruebas con token real). |
