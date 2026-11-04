package com.example.app.auth;

import java.util.UUID;

/**
 * Notificaciones de seguridad al usuario (cambio de contrasena, MFA, etc.).
 * PENDIENTE por proyecto: implementar el envio por email (ver docs/security/ESTADO_CHECKLIST.md).
 */
public interface SecurityNotifier {
    void notify(UUID userId, String event);
}
