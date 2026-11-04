# Inventario de datos personales (Ley 7593/2025 — registro de actividades de tratamiento)

Completar por proyecto y **actualizar en cada cambio que toque datos personales** (casilla del PR). Minimización primero: no pedir datos "por si acaso".

| Entidad / tabla | Campo | Categoría (público/interno/confidencial/sensible) | Finalidad | Base legal | Plazo de conservación | Quién accede (rol/permiso) | Cifrado | Proveedor / ubicación |
|---|---|---|---|---|---|---|---|---|
| `users` | `email`, `full_name` | confidencial | Autenticación y trazabilidad de operaciones | Ejecución del contrato / interés legítimo | Mientras la cuenta exista + *(definir)* | `user:read` | — | BD *(ubicación)* |
| `users` | `password_hash` | confidencial | Autenticación | Seguridad | Mientras la cuenta exista | Nadie (solo servicio de login) | Argon2id | BD |
| `users` | `mfa_secret_enc` | sensible | Segundo factor | Seguridad | Mientras MFA activo | Nadie (solo servicio MFA) | AES-256-GCM | BD |
| `audit_log` | `ip`, `user_agent`, `user_id` | confidencial | Seguridad y evidencia | Obligación legal / interés legítimo | 12 meses en línea + archivo (definir, hasta 5 años) | `audit:read` | — | BD / almacén de logs |
| `consents` | todos | confidencial | Prueba del consentimiento | Obligación legal | Mientras sea necesaria para acreditarlo | — | — | BD |
| *(clientes, ventas, crédito…)* | | | | | | | | |

## Derechos del titular (respuesta ≤ 30 días, sin costo)
Procedimiento: `data_subject_requests` registra cada solicitud y su resolución (auditada). Acceso/portabilidad → exportación JSON/CSV;
rectificación → edición; supresión → **anonimizar** si hay obligación de conservar (facturación) o borrar; oposición → cesar el tratamiento.
Backups: la supresión se aplica en producción de inmediato y en copias al rotar; mantener lista de supresiones para reaplicar al restaurar.

## Contacto de privacidad / DPO
*(nombre, correo, canal)*
