package com.example.app.auth;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.common.RateLimiter;
import com.example.app.config.AppProperties;
import com.example.app.security.PasswordHasher;
import com.example.app.user.UserRecord;
import com.example.app.user.UserRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Verificacion de credenciales: respuestas indistinguibles (usuario inexistente / mala clave / bloqueado / desactivado),
 * hash senuelo para igualar tiempos, limites por IP y por cuenta, bloqueo temporal con backoff y rehash transparente.
 */
@Service
public class LoginService {
    public enum Status { AUTHENTICATED, MFA_REQUIRED, FAILED, RATE_LIMITED }

    public record Outcome(Status status, UserRecord user, long retryAfterSeconds) {}

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final RateLimiter limiter;
    private final AuditService audit;
    private final AppProperties.Login cfg;

    public LoginService(UserRepository users, PasswordHasher hasher, RateLimiter limiter, AuditService audit, AppProperties props) {
        this.users = users;
        this.hasher = hasher;
        this.limiter = limiter;
        this.audit = audit;
        this.cfg = props.security().login();
    }

    public static String normalizeEmail(String email) {
        return email == null ? "" : email.strip().toLowerCase(Locale.ROOT);
    }

    public Outcome attempt(String rawEmail, String password, String ip) {
        String email = normalizeEmail(rawEmail);

        long wait = limiter.tryAcquire("login-ip:" + ip, cfg.ipLimitPerMinute(), Duration.ofMinutes(1));
        if (wait == 0) wait = limiter.tryAcquire("login-acct:" + email, cfg.accountLimitPerMinute(), Duration.ofMinutes(1));
        if (wait > 0) {
            audit.recordFor(null, null, "auth.login.rate_limited", Result.DENIED, "session", "login", "rate_limit", Map.of());
            return new Outcome(Status.RATE_LIMITED, null, wait);
        }

        Optional<UserRecord> found = users.findByEmail(email);
        String why = "unknown_user";
        boolean ok = false;
        if (found.isPresent()) {
            UserRecord u = found.get();
            if (!u.active()) {
                why = "inactive";
                hasher.burnDecoy(password);
            } else if (u.locked(Instant.now())) {
                why = "locked";
                hasher.burnDecoy(password);
            } else if (hasher.matches(password, u.passwordHash())) {
                ok = true;
            } else {
                why = "bad_credentials";
                users.registerFailedAttempt(u.id(), cfg.maxFailedAttempts(), cfg.lockBaseSeconds(), cfg.lockMaxSeconds());
            }
        } else {
            hasher.burnDecoy(password);
        }

        if (!ok) {
            // El motivo exacto va SOLO a la auditoria interna; al cliente siempre se responde lo mismo.
            audit.recordFor(found.map(UserRecord::tenantId).orElse(null), found.map(UserRecord::id).orElse(null),
                    "auth.login.failed", Result.DENIED, "session", "login", why, Map.of());
            return new Outcome(Status.FAILED, null, 0);
        }

        UserRecord u = found.get();
        if (hasher.needsRehash(u.passwordHash())) {
            users.updatePasswordHash(u.id(), hasher.hash(password));       // rehash transparente
        }
        users.registerSuccessfulLogin(u.id());
        audit.recordFor(u.tenantId(), u.id(), "auth.login.password_ok", Result.OK, "session", "login", null,
                Map.of("mfa", u.mfaEnabled()));
        return new Outcome(u.mfaEnabled() ? Status.MFA_REQUIRED : Status.AUTHENTICATED, u, 0);
    }
}
