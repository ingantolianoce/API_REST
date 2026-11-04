---
name: Revisión periódica de seguridad
about: Revisión trimestral de la plantilla / del proyecto
title: "Revisión de seguridad AAAA-Qn"
labels: seguridad, revision-periodica
---

Seguir `docs/security/CICLO_DE_ACTUALIZACION.md`. Marcar cada punto con evidencia (enlace a PR/commit).

### 1. Normativa y estándares (¿hay versión nueva o cambios?)
- [ ] OWASP ASVS (nivel 2/3) · OWASP Top 10 · Cheat Sheets (Password Storage, Session, Authentication, Authorization)
- [ ] NIST SP 800-63B (revisiones) · RFC 8725 (JWT) · parámetros Argon2id recomendados por OWASP
- [ ] Paraguay: reglamento de la Ley 7593/2025 (decreto), resoluciones de la ANPDP, Leyes 6534, 6822, 4868, normativa DNIT/SIFEN

### 2. Stack y dependencias
- [ ] Spring Boot / Spring Security / Spring Session (soporte vigente, avisos de seguridad)
- [ ] Java (LTS vigente), PostgreSQL (versión soportada), Vue / Vite / Node
- [ ] Dependabot al día; sin vulnerabilidades altas/críticas abiertas (Maven, npm, imágenes Docker)
- [ ] Versiones de GitHub Actions y de gitleaks/CodeQL actualizadas

### 3. Controles y pruebas
- [ ] CI verde (tests, CodeQL, secretos, auditoría de dependencias)
- [ ] Parámetros Argon2id re-medidos en el servidor real (< 1 s por hash)
- [ ] Prueba de restauración de backup del último mes documentada
- [ ] Revisión de accesos: cuentas inactivas, roles acumulados, cuentas de servicio
- [ ] Simulacro de incidente (72 h) si pasaron 6 meses

### 4. Cierre
- [ ] Actualizar documentos, código base y tests; `CHANGELOG.md` y `.template/VERSION`
- [ ] Registrar la revisión en `docs/security/REGISTRO_REVISIONES.md`
- [ ] Propagar a proyectos derivados (`scripts/template-sync.sh`)
