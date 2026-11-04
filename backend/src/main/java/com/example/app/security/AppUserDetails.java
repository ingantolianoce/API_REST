package com.example.app.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Principal que vive en la sesion del servidor. NO contiene el hash de la contrasena.
 * Las autoridades son PERMISOS (recurso:accion), no nombres de rol: el codigo verifica permisos.
 * Si cambian los roles del usuario se revocan sus sesiones (los permisos se recalculan al reingresar).
 */
public final class AppUserDetails implements UserDetails {
    private static final long serialVersionUID = 1L;

    private final UUID id;
    private final UUID tenantId;
    private final String email;
    private final String fullName;
    private final HashSet<String> roles;
    private final HashSet<String> permissions;
    private final boolean mfaEnabled;
    private final boolean mfaRequired;
    private final boolean mustChangePassword;

    public AppUserDetails(UUID id, UUID tenantId, String email, String fullName, Set<String> roles,
                          Set<String> permissions, boolean mfaEnabled, boolean mfaRequired, boolean mustChangePassword) {
        this.id = id;
        this.tenantId = tenantId;
        this.email = email;
        this.fullName = fullName;
        this.roles = new HashSet<>(roles);
        this.permissions = new HashSet<>(permissions);
        this.mfaEnabled = mfaEnabled;
        this.mfaRequired = mfaRequired;
        this.mustChangePassword = mustChangePassword;
    }

    public UUID id() { return id; }
    public UUID tenantId() { return tenantId; }
    public String email() { return email; }
    public String fullName() { return fullName; }
    public Set<String> roles() { return Set.copyOf(roles); }
    public Set<String> permissions() { return Set.copyOf(permissions); }
    public boolean mfaEnabled() { return mfaEnabled; }
    public boolean mfaRequired() { return mfaRequired; }
    public boolean mustChangePassword() { return mustChangePassword; }

    public AppUserDetails withMfaEnabled() {
        return new AppUserDetails(id, tenantId, email, fullName, roles, permissions, true, mfaRequired, mustChangePassword);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toUnmodifiableSet());
    }

    /** El principal de sesion nunca porta el hash. */
    @Override public String getPassword() { return null; }
    /** Identificador estable (no el email): es el nombre de principal para indexar y revocar sesiones. */
    @Override public String getUsername() { return id.toString(); }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}
