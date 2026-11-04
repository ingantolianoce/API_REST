package com.example.app.auth;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.common.ApiException;
import com.example.app.common.RateLimiter;
import com.example.app.security.PasswordHasher;
import com.example.app.security.PasswordPolicy;
import com.example.app.user.UserRecord;
import com.example.app.user.UserRepository;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountService {
    private final UserRepository users;
    private final PasswordHasher hasher;
    private final PasswordPolicy policy;
    private final SessionService sessions;
    private final RateLimiter limiter;
    private final AuditService audit;
    private final SecurityNotifier notifier;

    public AccountService(UserRepository users, PasswordHasher hasher, PasswordPolicy policy, SessionService sessions,
                          RateLimiter limiter, AuditService audit, SecurityNotifier notifier) {
        this.users = users;
        this.hasher = hasher;
        this.policy = policy;
        this.sessions = sessions;
        this.limiter = limiter;
        this.audit = audit;
        this.notifier = notifier;
    }

    /**
     * Cambio de contrasena: reautentica con la actual, aplica la politica, REVOCA TODAS las sesiones
     * (incluida la actual) y notifica al usuario.
     */
    @Transactional
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        UserRecord u = users.findById(userId).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED"));
        if (limiter.tryAcquire("reauth:" + userId, 5, Duration.ofMinutes(5)) > 0) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED");
        }
        if (!hasher.matches(currentPassword, u.passwordHash())) {
            audit.record("auth.password.change", Result.DENIED, "account", "change_password", "reauth_failed", Map.of());
            throw new ApiException(HttpStatus.FORBIDDEN, "REAUTH_FAILED");
        }
        List<String> context = new ArrayList<>();
        context.add(u.email().split("@")[0]);
        for (String part : u.fullName().split("\\s+")) context.add(part);
        context.add("app");
        List<String> violations = policy.validate(newPassword, context);
        if (newPassword.equals(currentPassword)) violations = List.of("PASSWORD_REUSED");
        if (!violations.isEmpty()) {
            throw new PasswordRejectedException(violations);
        }
        users.changePassword(u.id(), hasher.hash(newPassword));
        int revoked = sessions.revokeAll(u.id());
        audit.record("auth.password.changed", Result.OK, "account", "change_password", null, Map.of("revoked_sessions", revoked));
        notifier.notify(u.id(), "password_changed");
    }

    public static class PasswordRejectedException extends ApiException {
        private final List<String> violations;

        public PasswordRejectedException(List<String> violations) {
            super(HttpStatus.UNPROCESSABLE_ENTITY, "PASSWORD_REJECTED");
            this.violations = List.copyOf(violations);
        }

        public List<String> violations() { return violations; }
    }
}
