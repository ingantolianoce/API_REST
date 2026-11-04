package com.example.app.auth;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.common.ApiException;
import com.example.app.common.ClientInfo;
import com.example.app.security.AppUserDetails;
import com.example.app.user.UserRecord;
import com.example.app.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    public record LoginRequest(@NotBlank @Size(max = 254) String email, @NotBlank @Size(max = 256) String password) {}
    public record MfaVerifyRequest(@NotBlank @Size(max = 32) String code) {}
    public record ChangePasswordRequest(@NotBlank @Size(max = 256) String currentPassword,
                                        @NotBlank @Size(max = 256) String newPassword) {}
    public record MfaSetupRequest(@NotBlank @Size(max = 256) String currentPassword) {}
    public record MfaConfirmRequest(@NotBlank @Size(max = 16) String code) {}
    public record LoginResponse(String status, boolean mustChangePassword, boolean mfaEnrollmentRequired) {}

    private final LoginService login;
    private final MfaService mfa;
    private final AccountService accounts;
    private final SessionService sessions;
    private final UserRepository users;
    private final AuditService audit;

    public AuthController(LoginService login, MfaService mfa, AccountService accounts, SessionService sessions,
                          UserRepository users, AuditService audit) {
        this.login = login;
        this.mfa = mfa;
        this.accounts = accounts;
        this.sessions = sessions;
        this.users = users;
        this.audit = audit;
    }

    /** Entrega el token CSRF en la cookie XSRF-TOKEN (la SPA lo reenvia en X-XSRF-TOKEN). */
    @GetMapping("/csrf")
    @PreAuthorize("permitAll()")
    public ResponseEntity<Void> csrf(CsrfToken token) {
        token.getToken();   // fuerza la creacion/escritura de la cookie
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest body, HttpServletRequest req, HttpServletResponse res) {
        var outcome = login.attempt(body.email(), body.password(), ClientInfo.ip(req));
        switch (outcome.status()) {
            case RATE_LIMITED:
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .header(HttpHeaders.RETRY_AFTER, String.valueOf(outcome.retryAfterSeconds()))
                        .body(Map.of("code", "RATE_LIMITED"));
            case FAILED:
                // Misma respuesta para usuario inexistente, mala clave, cuenta bloqueada o desactivada.
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("code", "INVALID_CREDENTIALS"));
            case MFA_REQUIRED:
                sessions.startMfaPending(req, outcome.user().id());
                return ResponseEntity.ok(new LoginResponse("MFA_REQUIRED", false, false));
            default:
                AppUserDetails principal = users.toPrincipal(outcome.user());
                sessions.establish(req, res, principal);
                return ResponseEntity.ok(new LoginResponse("OK", principal.mustChangePassword(),
                        principal.mfaRequired() && !principal.mfaEnabled()));
        }
    }

    @PostMapping("/mfa/verify")
    @PreAuthorize("permitAll()")
    public ResponseEntity<?> verifyMfa(@Valid @RequestBody MfaVerifyRequest body, HttpServletRequest req, HttpServletResponse res) {
        HttpSession s = req.getSession(false);
        ResponseEntity<Map<String, String>> invalid = ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("code", "MFA_FAILED"));
        if (s == null || s.getAttribute(SessionService.ATTR_MFA_USER) == null) return invalid;

        long at = (Long) s.getAttribute(SessionService.ATTR_MFA_AT);
        int tries = (Integer) s.getAttribute(SessionService.ATTR_MFA_TRIES);
        if (Instant.now().getEpochSecond() - at > SessionService.MFA_PENDING_SECONDS || tries >= SessionService.MFA_MAX_TRIES) {
            s.invalidate();
            return invalid;
        }
        s.setAttribute(SessionService.ATTR_MFA_TRIES, tries + 1);
        UUID userId = UUID.fromString((String) s.getAttribute(SessionService.ATTR_MFA_USER));
        UserRecord u = users.findById(userId).filter(UserRecord::active).orElse(null);
        if (u == null || !mfa.verifyLogin(u, body.code())) return invalid;

        AppUserDetails principal = users.toPrincipal(u);
        sessions.establish(req, res, principal);
        return ResponseEntity.ok(new LoginResponse("OK", principal.mustChangePassword(), false));
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> logout(HttpServletRequest req) {
        audit.record("auth.logout", Result.OK, "session", "logout", null, Map.of());
        sessions.logout(req);
        return ResponseEntity.noContent().build();
    }

    /** Cambia la contrasena (reautenticacion con la actual) y revoca TODAS las sesiones; hay que volver a ingresar. */
    @PostMapping("/password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePasswordRequest body,
                                               @AuthenticationPrincipal AppUserDetails me, HttpServletRequest req) {
        accounts.changePassword(me.id(), body.currentPassword(), body.newPassword());
        sessions.logout(req);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/mfa/setup")
    @PreAuthorize("isAuthenticated()")
    public MfaService.Setup mfaSetup(@Valid @RequestBody MfaSetupRequest body, @AuthenticationPrincipal AppUserDetails me) {
        return mfa.setup(me.id(), body.currentPassword());
    }

    @PostMapping("/mfa/confirm")
    @PreAuthorize("isAuthenticated()")
    public Map<String, List<String>> mfaConfirm(@Valid @RequestBody MfaConfirmRequest body, @AuthenticationPrincipal AppUserDetails me,
                                                HttpServletRequest req, HttpServletResponse res) {
        List<String> codes = mfa.confirm(me.id(), body.code());
        // Cambio de privilegios (ahora con MFA): nuevo principal y nuevo ID de sesion.
        sessions.refreshPrincipal(req, res, me.withMfaEnabled());
        return Map.of("recoveryCodes", codes);
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public Map<String, Object> me(@AuthenticationPrincipal AppUserDetails me) {
        return Map.of("id", me.id(), "email", me.email(), "fullName", me.fullName(), "roles", me.roles(),
                "permissions", me.permissions(), "mfaEnabled", me.mfaEnabled(), "mustChangePassword", me.mustChangePassword());
    }
}
