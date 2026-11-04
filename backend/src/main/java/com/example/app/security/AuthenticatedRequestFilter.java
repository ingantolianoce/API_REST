package com.example.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 1) Enriquece el MDC con user_id/tenant_id (logs y auditoria correlacionables).
 * 2) Compuerta de estado de cuenta (falla cerrado): quien debe cambiar la contrasena o enrolar MFA
 *    (rol privilegiado sin MFA) solo puede llamar a los endpoints necesarios para resolverlo.
 * NO es un @Component: se registra solo dentro de la cadena de Spring Security (evita doble registro como filtro de servlet).
 */
public class AuthenticatedRequestFilter extends OncePerRequestFilter {
    private static final Set<String> ALWAYS = Set.of("/api/v1/auth/csrf", "/api/v1/auth/logout", "/api/v1/auth/me");
    private static final Set<String> PASSWORD = Set.of("/api/v1/auth/password");
    private static final Set<String> MFA = Set.of("/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/confirm");

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a != null && a.getPrincipal() instanceof AppUserDetails u) {
            MDC.put("user_id", u.id().toString());
            MDC.put("tenant_id", u.tenantId().toString());
            String path = req.getRequestURI().substring(req.getContextPath().length());
            if (!ALWAYS.contains(path)) {
                if (u.mustChangePassword() && !PASSWORD.contains(path)) {
                    deny(res, "PASSWORD_CHANGE_REQUIRED");
                    return;
                }
                if (u.mfaRequired() && !u.mfaEnabled() && !MFA.contains(path) && !PASSWORD.contains(path)) {
                    deny(res, "MFA_ENROLLMENT_REQUIRED");
                    return;
                }
            }
        }
        chain.doFilter(req, res);
    }

    private static void deny(HttpServletResponse res, String code) throws IOException {
        res.setStatus(HttpServletResponse.SC_FORBIDDEN);
        res.setContentType("application/json");
        res.getWriter().write("{\"code\":\"" + code + "\"}");
    }
}
