package com.example.app.user;

import com.example.app.security.AppUserDetails;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Acceso a datos con SQL parametrizado. REGLA: toda consulta de recursos de negocio filtra por tenant_id
 * (anti-IDOR / multi-tenant). Solo los metodos de autenticacion buscan sin tenant (el login aun no lo conoce).
 */
@Repository
public class UserRepository {
    private static final String COLS = """
            id, tenant_id, email, full_name, password_hash, status, must_change_password, mfa_enabled, mfa_secret_enc,
            mfa_last_step, failed_attempts, locked_until, created_at""";

    private static final RowMapper<UserRecord> MAPPER = (ResultSet rs, int n) -> mapRow(rs);

    private final JdbcClient jdbc;

    public UserRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    private static UserRecord mapRow(ResultSet rs) throws SQLException {
        var locked = rs.getTimestamp("locked_until");
        long step = rs.getLong("mfa_last_step");
        return new UserRecord(
                rs.getObject("id", UUID.class), rs.getObject("tenant_id", UUID.class), rs.getString("email"),
                rs.getString("full_name"), rs.getString("password_hash"), rs.getString("status"),
                rs.getBoolean("must_change_password"), rs.getBoolean("mfa_enabled"), rs.getString("mfa_secret_enc"),
                rs.wasNull() ? null : step, rs.getInt("failed_attempts"),
                locked == null ? null : locked.toInstant(), rs.getTimestamp("created_at").toInstant());
    }

    // ---- Autenticacion (sin tenant: aun no se conoce) ----

    public Optional<UserRecord> findByEmail(String email) {
        return jdbc.sql("SELECT " + COLS + " FROM users WHERE lower(email) = lower(:email) AND deleted_at IS NULL")
                .param("email", email).query(MAPPER).optional();
    }

    public Optional<UserRecord> findById(UUID id) {
        return jdbc.sql("SELECT " + COLS + " FROM users WHERE id = :id AND deleted_at IS NULL")
                .param("id", id).query(MAPPER).optional();
    }

    /** Incremento ATOMICO (sin carrera) + bloqueo temporal con backoff exponencial. */
    public void registerFailedAttempt(UUID id, int maxAttempts, int baseSeconds, int capSeconds) {
        jdbc.sql("""
                UPDATE users SET
                    failed_attempts = failed_attempts + 1,
                    locked_until = CASE WHEN failed_attempts + 1 >= :max
                        THEN now() + make_interval(secs => LEAST(CAST(:cap AS double precision),
                                       :base * power(2, failed_attempts + 1 - :max)))
                        ELSE locked_until END
                WHERE id = :id
                """)
                .param("id", id).param("max", maxAttempts).param("base", (double) baseSeconds).param("cap", (double) capSeconds)
                .update();
    }

    public void registerSuccessfulLogin(UUID id) {
        jdbc.sql("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = :id")
                .param("id", id).update();
    }

    public void updatePasswordHash(UUID id, String hash) {
        jdbc.sql("UPDATE users SET password_hash = :h, updated_at = now() WHERE id = :id")
                .param("h", hash).param("id", id).update();
    }

    public void changePassword(UUID id, String hash) {
        jdbc.sql("""
                UPDATE users SET password_hash = :h, password_changed_at = now(), must_change_password = false,
                       failed_attempts = 0, locked_until = NULL, updated_at = now(), updated_by = :id, version = version + 1
                WHERE id = :id
                """).param("h", hash).param("id", id).update();
    }

    public AppUserDetails toPrincipal(UserRecord u) {
        Set<String> roles = new HashSet<>(jdbc.sql("""
                SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = :id
                """).param("id", u.id()).query(String.class).list());
        Set<String> perms = new HashSet<>(jdbc.sql("""
                SELECT DISTINCT rp.permission_code FROM user_roles ur
                JOIN role_permissions rp ON rp.role_id = ur.role_id WHERE ur.user_id = :id
                """).param("id", u.id()).query(String.class).list());
        boolean mfaRequired = jdbc.sql("""
                SELECT COALESCE(bool_or(r.mfa_required), false) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
                WHERE ur.user_id = :id
                """).param("id", u.id()).query(Boolean.class).single();
        return new AppUserDetails(u.id(), u.tenantId(), u.email(), u.fullName(), roles, perms,
                u.mfaEnabled(), mfaRequired, u.mustChangePassword());
    }

    // ---- MFA ----

    public void storePendingMfaSecret(UUID id, String encrypted) {
        jdbc.sql("UPDATE users SET mfa_secret_enc = :s, mfa_enabled = false, mfa_last_step = NULL, updated_at = now() WHERE id = :id")
                .param("s", encrypted).param("id", id).update();
    }

    public void enableMfa(UUID id) {
        jdbc.sql("UPDATE users SET mfa_enabled = true, updated_at = now(), updated_by = :id, version = version + 1 WHERE id = :id")
                .param("id", id).update();
    }

    /** Marca el paso TOTP como usado. @return false si ya se uso (reutilizacion de codigo). */
    public boolean consumeTotpStep(UUID id, long step) {
        return jdbc.sql("UPDATE users SET mfa_last_step = :s WHERE id = :id AND (mfa_last_step IS NULL OR mfa_last_step < :s)")
                .param("s", step).param("id", id).update() == 1;
    }

    public void replaceRecoveryCodes(UUID userId, List<String> hashes) {
        jdbc.sql("DELETE FROM recovery_codes WHERE user_id = :u").param("u", userId).update();
        for (String h : hashes) {
            jdbc.sql("INSERT INTO recovery_codes (user_id, code_hash) VALUES (:u, :h)").param("u", userId).param("h", h).update();
        }
    }

    /** Consume un codigo de recuperacion (un solo uso, atomico). */
    public boolean consumeRecoveryCode(UUID userId, String hash) {
        return jdbc.sql("UPDATE recovery_codes SET used_at = now() WHERE user_id = :u AND code_hash = :h AND used_at IS NULL")
                .param("u", userId).param("h", hash).update() == 1;
    }

    // ---- Recursos del comercio (SIEMPRE con tenant_id) ----

    public Optional<UserRecord> findByIdAndTenant(UUID id, UUID tenantId) {
        return jdbc.sql("SELECT " + COLS + " FROM users WHERE id = :id AND tenant_id = :t AND deleted_at IS NULL")
                .param("id", id).param("t", tenantId).query(MAPPER).optional();
    }

    public List<UserRecord> listByTenant(UUID tenantId, int limit, int offset) {
        return jdbc.sql("SELECT " + COLS + " FROM users WHERE tenant_id = :t AND deleted_at IS NULL ORDER BY created_at, id LIMIT :l OFFSET :o")
                .param("t", tenantId).param("l", limit).param("o", offset).query(MAPPER).list();
    }

    public long countByTenant(UUID tenantId) {
        return jdbc.sql("SELECT count(*) FROM users WHERE tenant_id = :t AND deleted_at IS NULL")
                .param("t", tenantId).query(Long.class).single();
    }

    public long countAll() {
        return jdbc.sql("SELECT count(*) FROM users").query(Long.class).single();
    }

    public UUID insert(UUID tenantId, String email, String fullName, String hash, boolean mustChange, UUID createdBy) {
        return jdbc.sql("""
                INSERT INTO users (tenant_id, email, full_name, password_hash, must_change_password, created_by, updated_by)
                VALUES (:t, :e, :n, :h, :m, :c, :c) RETURNING id
                """)
                .param("t", tenantId).param("e", email).param("n", fullName).param("h", hash).param("m", mustChange).param("c", createdBy)
                .query(UUID.class).single();
    }

    public void disable(UUID id, UUID tenantId, UUID actor, String reason) {
        jdbc.sql("""
                UPDATE users SET status = 'DISABLED', deactivated_at = now(), deactivation_reason = :r,
                       updated_at = now(), updated_by = :a, version = version + 1
                WHERE id = :id AND tenant_id = :t
                """).param("r", reason).param("a", actor).param("id", id).param("t", tenantId).update();
    }

    // ---- Roles ----

    public List<String> roleNames(UUID userId) {
        return jdbc.sql("SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = :u ORDER BY r.name")
                .param("u", userId).query(String.class).list();
    }

    public Set<String> permissionsOfRole(String roleName) {
        return new HashSet<>(jdbc.sql("""
                SELECT rp.permission_code FROM roles r JOIN role_permissions rp ON rp.role_id = r.id WHERE r.name = :n
                """).param("n", roleName).query(String.class).list());
    }

    public boolean roleExists(String roleName) {
        return jdbc.sql("SELECT count(*) FROM roles WHERE name = :n").param("n", roleName).query(Long.class).single() > 0;
    }

    public void replaceRoles(UUID userId, UUID tenantId, Set<String> roleNames, UUID grantedBy) {
        jdbc.sql("DELETE FROM user_roles WHERE user_id = :u").param("u", userId).update();
        for (String name : roleNames) {
            jdbc.sql("""
                    INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by)
                    SELECT :u, r.id, :t, :g FROM roles r WHERE r.name = :n
                    """).param("u", userId).param("t", tenantId).param("g", grantedBy).param("n", name).update();
        }
    }

    /** Bloquea la fila del comercio para serializar cambios que afectan "ultimo superadmin". */
    public void lockTenant(UUID tenantId) {
        jdbc.sql("SELECT id FROM tenants WHERE id = :t FOR UPDATE").param("t", tenantId).query(UUID.class).optional();
    }

    public long countActiveWithRole(UUID tenantId, String roleName) {
        return jdbc.sql("""
                SELECT count(*) FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
                WHERE u.tenant_id = :t AND r.name = :n AND u.status = 'ACTIVE' AND u.deleted_at IS NULL
                """).param("t", tenantId).param("n", roleName).query(Long.class).single();
    }

    // ---- Tenants (bootstrap) ----

    public UUID insertTenant(String legalName) {
        return jdbc.sql("INSERT INTO tenants (legal_name) VALUES (:n) RETURNING id").param("n", legalName).query(UUID.class).single();
    }

    public Instant dbNow() {
        return jdbc.sql("SELECT now()").query(java.sql.Timestamp.class).single().toInstant();
    }
}
