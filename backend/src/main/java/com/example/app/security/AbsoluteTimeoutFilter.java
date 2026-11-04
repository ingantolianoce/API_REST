package com.example.app.security;

import com.example.app.auth.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Timeout ABSOLUTO de sesion (ademas del de inactividad): pasado el limite, la sesion se invalida aunque haya actividad. */
public class AbsoluteTimeoutFilter extends OncePerRequestFilter {
    private final Duration absolute;

    public AbsoluteTimeoutFilter(Duration absolute) {
        this.absolute = absolute;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        HttpSession s = req.getSession(false);
        if (s != null) {
            Object at = s.getAttribute(SessionService.ATTR_AUTH_AT);
            if (at instanceof Long epoch && Instant.now().getEpochSecond() - epoch > absolute.toSeconds()) {
                s.invalidate();
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(req, res);
    }
}
