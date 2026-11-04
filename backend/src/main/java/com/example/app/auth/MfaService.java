package com.example.app.auth;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.common.ApiException;
import com.example.app.common.RateLimiter;
import com.example.app.security.FieldEncryptor;
import com.example.app.security.PasswordHasher;
import com.example.app.security.TotpService;
import com.example.app.user.UserRecord;
import com.example.app.user.UserRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** MFA con TOTP (RFC 6238) y codigos de recuperacion de un solo uso. Secreto cifrado en reposo. */
@Service
public class MfaService {
    public record Setup(String secret, String otpauthUri) {}

    private final UserRepository users;
    private final TotpService totp;
    private final FieldEncryptor crypto;
    private final PasswordHasher hasher;
    private final RateLimiter limiter;
    private final AuditService audit;

    public MfaService(UserRepository users, TotpService totp, FieldEncryptor crypto, PasswordHasher hasher,
                      RateLimiter limiter, AuditService audit) {
        this.users = users;
        this.totp = totp;
        this.crypto = crypto;
        this.hasher = hasher;
        this.limiter = limiter;
        this.audit = audit;
    }

    /** Requiere reautenticacion (contrasena actual) antes de iniciar el alta de MFA. */
    @Transactional
    public Setup setup(UUID userId, String currentPassword) {
        UserRecord u = users.findById(userId).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED"));
        if (limiter.tryAcquire("reauth:" + userId, 5, Duration.ofMinutes(5)) > 0) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED");
        }
        if (!hasher.matches(currentPassword, u.passwordHash())) {
            audit.record("auth.mfa.setup", Result.DENIED, "mfa", "setup", "reauth_failed", Map.of());
            throw new ApiException(HttpStatus.FORBIDDEN, "REAUTH_FAILED");
        }
        if (u.mfaEnabled()) throw new ApiException(HttpStatus.CONFLICT, "MFA_ALREADY_ENABLED");
        byte[] secret = totp.newSecret();
        users.storePendingMfaSecret(u.id(), crypto.encrypt(secret, aad(u.id())));
        audit.record("auth.mfa.setup", Result.OK, "mfa", "setup", null, Map.of());
        return new Setup(totp.base32(secret), totp.otpauthUri("App", u.email(), secret));
    }

    /** Confirma el alta con un codigo valido; devuelve los codigos de recuperacion (se muestran UNA vez). */
    @Transactional
    public List<String> confirm(UUID userId, String code) {
        UserRecord u = users.findById(userId).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED"));
        if (u.mfaEnabled() || u.mfaSecretEnc() == null) throw new ApiException(HttpStatus.CONFLICT, "MFA_NOT_PENDING");
        if (limiter.tryAcquire("mfa:" + userId, 10, Duration.ofMinutes(1)) > 0) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED");
        }
        OptionalLong step = totp.verify(crypto.decrypt(u.mfaSecretEnc(), aad(u.id())), code, Instant.now());
        if (step.isEmpty() || !users.consumeTotpStep(u.id(), step.getAsLong())) {
            audit.record("auth.mfa.confirm", Result.DENIED, "mfa", "confirm", "bad_code", Map.of());
            throw new ApiException(HttpStatus.FORBIDDEN, "MFA_CODE_INVALID");
        }
        users.enableMfa(u.id());
        List<String> codes = RecoveryCodes.generate(10);
        users.replaceRecoveryCodes(u.id(), codes.stream().map(RecoveryCodes::hash).collect(Collectors.toList()));
        audit.record("auth.mfa.enabled", Result.OK, "mfa", "enable", null, Map.of());
        return codes;
    }

    /** Verifica el segundo factor del login: TOTP (sin reutilizacion) o codigo de recuperacion de un solo uso. */
    @Transactional
    public boolean verifyLogin(UserRecord u, String code) {
        if (limiter.tryAcquire("mfa:" + u.id(), 10, Duration.ofMinutes(1)) > 0) return false;
        boolean ok;
        String kind;
        if (RecoveryCodes.looksLikeRecoveryCode(code)) {
            kind = "recovery_code";
            ok = users.consumeRecoveryCode(u.id(), RecoveryCodes.hash(code));
        } else {
            kind = "totp";
            OptionalLong step = u.mfaSecretEnc() == null ? OptionalLong.empty()
                    : totp.verify(crypto.decrypt(u.mfaSecretEnc(), aad(u.id())), code, Instant.now());
            ok = step.isPresent() && users.consumeTotpStep(u.id(), step.getAsLong());
        }
        audit.recordFor(u.tenantId(), u.id(), ok ? "auth.mfa.ok" : "auth.mfa.failed", ok ? Result.OK : Result.DENIED,
                "session", "mfa", kind, Map.of());
        return ok;
    }

    private static String aad(UUID userId) {
        return "user:" + userId + ":mfa";
    }
}
