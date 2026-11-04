package com.example.app.user;

import java.time.Instant;
import java.util.UUID;

/** Fila de `users` para uso interno (incluye hash y secreto MFA cifrado). Nunca se serializa hacia el cliente. */
public record UserRecord(
        UUID id, UUID tenantId, String email, String fullName, String passwordHash, String status,
        boolean mustChangePassword, boolean mfaEnabled, String mfaSecretEnc, Long mfaLastStep,
        int failedAttempts, Instant lockedUntil, Instant createdAt) {

    public boolean active() { return "ACTIVE".equals(status); }
    public boolean locked(Instant now) { return lockedUntil != null && lockedUntil.isAfter(now); }
}
