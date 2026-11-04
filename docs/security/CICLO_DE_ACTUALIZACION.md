# Ciclo de actualización de la plantilla

La seguridad envejece: estándares, librerías y leyes cambian. Esta plantilla se **revisa cada trimestre** y ante eventos concretos,
y los cambios se propagan a los proyectos de forma controlada.

## 1. Cuándo se actualiza

| Disparador | Plazo |
|---|---|
| **Revisión trimestral** (5 de ene/abr/jul/oct): un workflow abre el issue con el checklist (`template-review-reminder.yml`) | dentro del trimestre |
| Vulnerabilidad en el **diseño o código base** (o CVE crítico en Spring/Vue/PostgreSQL/Java) | **crítica: ≤ 7 días**; alta: ≤ 30 días |
| Nueva versión de **OWASP ASVS / Top 10**, **NIST SP 800-63**, Cheat Sheets de OWASP, RFC 8725 | siguiente revisión (o antes si cambia un P0) |
| **Ley 7593**: decreto reglamentario, resoluciones de la ANPDP; cambios en Leyes 6534/6822/4868 o normativa DNIT/SIFEN | al publicarse; avisar a proyectos afectados |
| Fin de soporte de Spring Boot / Java LTS / PostgreSQL / Node usados | 3 meses antes |
| Un proyecto descubre un fallo o mejora general | cuando se reporte (PR a la plantilla) |

## 2. Cómo se actualiza (en el repositorio de la plantilla)

1. Abrir el issue de revisión (checklist en `.github/ISSUE_TEMPLATE/revision-seguridad.md`) y trabajar en una rama.
2. Verificar fuentes primarias y **anotar la fecha de verificación** en los documentos (no confiar en memoria).
3. Cambiar docs → código base → pruebas (un requisito sin prueba no se considera cumplido).
4. Actualizar `docs/security/ESTADO_CHECKLIST.md` y `STACK_SPRING_VUE.md` si cambió el mapa.
5. Actualizar dependencias (Dependabot) y re-medir parámetros (Argon2id) si aplica; anotar en `SECURITY_DECISIONS.md`.
6. `CHANGELOG.md`: entrada nueva separando **Documentos / CI** (sincronizable) de **Código base** (manual). Marcar **CRÍTICA** si corresponde.
7. Subir `.template/VERSION` (SemVer: MAJOR si cambia/agrega un P0 o rompe compatibilidad · MINOR control nuevo · PATCH correcciones).
8. Registrar la revisión en `REGISTRO_REVISIONES.md`, revisión por otra persona (CODEOWNERS), merge, etiqueta `vX.Y.Z` y *release*.

## 3. Cómo llega a los proyectos

* Cada proyecto tiene `.template/VERSION` y `.template/UPSTREAM`. El workflow **`template-update-check.yml`** (semanal) abre un issue si la plantilla tiene una versión mayor.
* **Documentos/CI/BD roles** (lista en `.template/managed-files.txt`): `scripts/template-sync.sh` los sobrescribe con la versión nueva (`--check` solo informa; `--ref vX.Y.Z` fija versión). Revisar `git diff`, correr los tests, commit.
* **Código base** (`backend/`, `frontend/`): se aplica a mano siguiendo el CHANGELOG, porque el paquete Java y el código del proyecto divergen.
  Atajo: `git diff --no-index <plantilla>/backend/src/main <proyecto>/backend/src/main` (ignorando el nombre del paquete).
* Un proyecto puede **diferir** solo con una excepción escrita en su `SECURITY_DECISIONS.md` (motivo, responsable, fecha de revisión).
* Plazos para proyectos: actualización CRÍTICA ≤ 7 días; resto, en el siguiente ciclo trimestral del proyecto.

## 4. Revisión trimestral — qué mirar (fuentes primarias)

* OWASP ASVS, Top 10, Cheat Sheets (Password Storage: ¿cambiaron los parámetros de Argon2id?); NIST SP 800-63B; RFC 8725.
* Paraguay: texto oficial y reglamento de la Ley 7593, ANPDP/MITIC; BCP/SEDECO (6534); MIC (6822); DNIT/SIFEN. *No es asesoría legal: validar con abogado.*
* Spring Boot / Security / Session (soporte, avisos), Java LTS, PostgreSQL, Vue/Vite/Node, Docker imágenes, GitHub Actions.
* Estado del CI, alertas de Dependabot/CodeQL, secretos expuestos.
* Re-medir Argon2id en el servidor de referencia; prueba de restauración de backup; revisión de accesos.

## 5. Responsables

* **Responsable de la plantilla** (dueño de la revisión y del release): definir nombre aquí al adoptarla → `________`
* **Revisor** (segunda persona para cambios de auth/authz/cripto): `________`
* Registrar a ambos en `.github/CODEOWNERS`.
