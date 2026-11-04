package com.example.app.auth;

import com.example.app.config.AppProperties;
import com.example.app.security.AppUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.UUID;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Service;

/** Ciclo de vida de sesiones: regeneracion de ID, timeouts por privilegio, estado MFA pendiente y revocacion. */
@Service
public class SessionService {
    public static final String ATTR_AUTH_AT = "AUTH_AT";
    public static final String ATTR_MFA_USER = "MFA_PENDING_USER";
    public static final String ATTR_MFA_AT = "MFA_PENDING_AT";
    public static final String ATTR_MFA_TRIES = "MFA_PENDING_TRIES";
    public static final int MFA_PENDING_SECONDS = 300;
    public static final int MFA_MAX_TRIES = 5;

    private final SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
    private final FindByIndexNameSessionRepository<?> sessions;
    private final AppProperties props;

    public SessionService(FindByIndexNameSessionRepository<?> sessions, AppProperties props) {
        this.sessions = sessions;
        this.props = props;
    }

    public SecurityContextRepository contextRepository() {
        return contextRepository;
    }

    /** Inicia una sesion autenticada. Siempre regenera el ID (anti fijacion) y fija timeouts segun privilegio. */
    public void establish(HttpServletRequest req, HttpServletResponse res, AppUserDetails principal) {
        HttpSession existing = req.getSession(false);
        if (existing != null) {
            existing.removeAttribute(ATTR_MFA_USER);
            existing.removeAttribute(ATTR_MFA_AT);
            existing.removeAttribute(ATTR_MFA_TRIES);
            req.changeSessionId();
        }
        HttpSession session = req.getSession(true);
        var auth = UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
        contextRepository.saveContext(ctx, req, res);
        if (session.getAttribute(ATTR_AUTH_AT) == null) {
            session.setAttribute(ATTR_AUTH_AT, Instant.now().getEpochSecond());
        }
        boolean privileged = principal.mfaRequired() || principal.roles().contains("superadmin");
        var idle = privileged ? props.security().session().idlePrivileged() : props.security().session().idleStandard();
        session.setMaxInactiveInterval((int) idle.toSeconds());
    }

    /** Re-emite la sesion con un principal actualizado (p. ej. tras activar MFA): cambio de privilegios => nuevo ID. */
    public void refreshPrincipal(HttpServletRequest req, HttpServletResponse res, AppUserDetails principal) {
        establish(req, res, principal);
    }

    public void startMfaPending(HttpServletRequest req, UUID userId) {
        HttpSession old = req.getSession(false);
        if (old != null) req.changeSessionId();
        HttpSession s = req.getSession(true);
        s.setAttribute(ATTR_MFA_USER, userId.toString());
        s.setAttribute(ATTR_MFA_AT, Instant.now().getEpochSecond());
        s.setAttribute(ATTR_MFA_TRIES, 0);
        s.setMaxInactiveInterval(MFA_PENDING_SECONDS);
    }

    public void logout(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        if (s != null) s.invalidate();
        SecurityContextHolder.clearContext();
    }

    /** Revoca TODAS las sesiones del usuario (cambio de contrasena/rol, desactivacion). */
    public int revokeAll(UUID userId) {
        var found = sessions.findByPrincipalName(userId.toString());
        found.keySet().forEach(sessions::deleteById);
        return found.size();
    }
}
