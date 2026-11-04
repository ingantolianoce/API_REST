package com.example.app.user;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.auth.SessionService;
import com.example.app.common.ApiException;
import com.example.app.security.AppUserDetails;
import com.example.app.security.PasswordGenerator;
import com.example.app.security.PasswordHasher;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Referencia de como aplicar las reglas de autorizacion:
 *  - el tenant sale SIEMPRE del principal autenticado, nunca del cliente;
 *  - un recurso ajeno responde 404 (no se revela su existencia);
 *  - solo se asigna/quita lo que se posee; nadie edita sus propios roles; el ultimo superadmin esta protegido;
 *  - los cambios de roles/estado revocan las sesiones afectadas y quedan auditados con valor anterior y nuevo.
 */
@Service
public class UserService {
    private static final String SUPERADMIN = "superadmin";

    public record UserView(UUID id, String email, String fullName, String status, boolean mfaEnabled, List<String> roles) {}
    public record CreatedUser(UserView user, String temporaryPassword) {}

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final AuditService audit;
    private final SessionService sessions;

    public UserService(UserRepository users, PasswordHasher hasher, AuditService audit, SessionService sessions) {
        this.users = users;
        this.hasher = hasher;
        this.audit = audit;
        this.sessions = sessions;
    }

    @Transactional(readOnly = true)
    public List<UserView> list(AppUserDetails actor, int page, int size) {
        int s = Math.min(Math.max(size, 1), 100);
        int p = Math.max(page, 0);
        return users.listByTenant(actor.tenantId(), s, p * s).stream().map(this::view).toList();
    }

    @Transactional(readOnly = true)
    public UserView get(AppUserDetails actor, UUID id) {
        return view(requireInTenant(actor, id));
    }

    /**
     * Alta con contrasena aleatoria de un solo uso y cambio forzado. Se muestra una vez al administrador.
     * (Sustituir por invitacion por email cuando el proyecto tenga correo: ver SECURITY_DECISIONS.md.)
     */
    @Transactional
    public CreatedUser create(AppUserDetails actor, String email, String fullName, List<String> roleNames) {
        Set<String> roles = new TreeSet<>(roleNames);
        assertAssignable(actor, roles);
        String normalized = email.strip().toLowerCase(java.util.Locale.ROOT);
        if (users.findByEmail(normalized).isPresent()) throw new ApiException(HttpStatus.CONFLICT, "EMAIL_IN_USE");
        String temp = PasswordGenerator.oneTime();
        UUID id = users.insert(actor.tenantId(), normalized, fullName.strip(), hasher.hash(temp), true, actor.id());
        users.replaceRoles(id, actor.tenantId(), roles, actor.id());
        audit.record("user.created", Result.OK, "user:" + id, "create", null, Map.of("roles", roles));
        return new CreatedUser(view(users.findByIdAndTenant(id, actor.tenantId()).orElseThrow()), temp);
    }

    @Transactional
    public UserView assignRoles(AppUserDetails actor, UUID targetId, List<String> roleNames) {
        users.lockTenant(actor.tenantId());                                   // serializa el chequeo de "ultimo superadmin"
        UserRecord target = requireInTenant(actor, targetId);
        if (target.id().equals(actor.id())) {
            audit.record("authz.denied", Result.DENIED, "user:" + targetId, "assign_roles", "self_role_edit", Map.of());
            throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN");        // nadie edita sus propios roles
        }
        Set<String> newRoles = new TreeSet<>(roleNames);
        Set<String> oldRoles = new TreeSet<>(users.roleNames(target.id()));
        Set<String> changed = new HashSet<>(newRoles);
        changed.addAll(oldRoles);
        Set<String> unchanged = new HashSet<>(newRoles);
        unchanged.retainAll(oldRoles);
        changed.removeAll(unchanged);
        assertAssignable(actor, changed);                                     // altas Y bajas: solo lo que el actor posee

        if (oldRoles.contains(SUPERADMIN) && !newRoles.contains(SUPERADMIN) && target.active()
                && users.countActiveWithRole(actor.tenantId(), SUPERADMIN) <= 1) {
            throw new ApiException(HttpStatus.CONFLICT, "LAST_SUPERADMIN");
        }
        users.replaceRoles(target.id(), actor.tenantId(), newRoles, actor.id());
        sessions.revokeAll(target.id());                                      // los permisos se recalculan al reingresar
        audit.record("user.roles.changed", Result.OK, "user:" + target.id(), "assign_roles", null,
                Map.of("old", oldRoles, "new", newRoles));
        return view(requireInTenant(actor, targetId));
    }

    @Transactional
    public void disable(AppUserDetails actor, UUID targetId, String reason) {
        users.lockTenant(actor.tenantId());
        UserRecord target = requireInTenant(actor, targetId);
        if (target.id().equals(actor.id())) throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN");
        assertAssignable(actor, new HashSet<>(users.roleNames(target.id())));      // no se desactiva a quien tiene mas poder
        if (!target.active()) return;
        if (users.roleNames(target.id()).contains(SUPERADMIN) && users.countActiveWithRole(actor.tenantId(), SUPERADMIN) <= 1) {
            throw new ApiException(HttpStatus.CONFLICT, "LAST_SUPERADMIN");
        }
        users.disable(target.id(), actor.tenantId(), actor.id(), reason);
        int revoked = sessions.revokeAll(target.id());
        audit.record("user.disabled", Result.OK, "user:" + target.id(), "disable", reason, Map.of("revoked_sessions", revoked));
    }

    // ---- reglas ----

    private UserRecord requireInTenant(AppUserDetails actor, UUID id) {
        return users.findByIdAndTenant(id, actor.tenantId())
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "NOT_FOUND"));   // 404 tambien para recursos ajenos
    }

    /** Solo se puede asignar (o quitar) un rol si el actor posee TODOS los permisos de ese rol. Anti-escalada. */
    private void assertAssignable(AppUserDetails actor, Set<String> roles) {
        for (String role : roles) {
            if (!users.roleExists(role)) throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "UNKNOWN_ROLE");
            if (!actor.permissions().containsAll(users.permissionsOfRole(role))) {
                audit.record("authz.denied", Result.DENIED, "role:" + role, "assign", "privilege_escalation", Map.of());
                throw new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN");
            }
        }
    }

    private UserView view(UserRecord u) {
        return new UserView(u.id(), u.email(), u.fullName(), u.status(), u.mfaEnabled(), users.roleNames(u.id()));
    }
}
