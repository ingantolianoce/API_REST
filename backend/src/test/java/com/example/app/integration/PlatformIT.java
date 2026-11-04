package com.example.app.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

class PlatformIT extends IntegrationTestBase {

    @Test
    void securityHeadersArePresent() throws Exception {
        mvc.perform(get("/actuator/health").secure(true)).andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Strict-Transport-Security", org.hamcrest.Matchers.containsString("max-age=31536000")))
                .andExpect(header().exists("Permissions-Policy"))
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(header().exists("X-Request-Id"));
    }

    @Test
    void healthEndpointDoesNotLeakDetailsAndOtherActuatorEndpointsAreClosed() throws Exception {
        String body = mvc.perform(get("/actuator/health")).andReturn().getResponse().getContentAsString();
        assertThat(body).contains("\"status\":\"UP\"").doesNotContain("components").doesNotContain("details").doesNotContain("jdbc");
        mvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/beans")).andExpect(status().isUnauthorized());
    }

    @Test
    void corsRejectsUnlistedOrigins() throws Exception {
        mvc.perform(get("/api/v1/auth/csrf").header("Origin", "https://evil.example"))
                .andExpect(status().isForbidden());
    }

    @Test
    void requestIdFromClientIsValidatedAgainstLogInjection() throws Exception {
        String evil = "abc\r\nX-Injected: 1";
        var res = mvc.perform(get("/actuator/health").header("X-Request-Id", evil)).andReturn().getResponse();
        assertThat(res.getHeader("X-Request-Id")).doesNotContain("\n").isNotEqualTo(evil);
        assertThat(res.getHeader("X-Injected")).isNull();
    }

    @Test
    void auditLogIsAppendOnlyEvenForTheApplicationUser() {
        jdbc.sql("INSERT INTO audit_log (event, result) VALUES ('test.event', 'OK')").update();
        assertThatThrownBy(() -> jdbc.sql("UPDATE audit_log SET result = 'DENIED'").update()).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("DELETE FROM audit_log").update()).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("TRUNCATE audit_log").update()).isInstanceOf(DataAccessException.class);
    }

    @Test
    void applicationDbUserHasNoDdlNorAccessToMigrationHistory() {
        assertThatThrownBy(() -> jdbc.sql("DROP TABLE users").update()).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("CREATE TABLE hack (id int)").update()).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("SELECT * FROM flyway_schema_history").query().listOfRows()).isInstanceOf(DataAccessException.class);
        assertThatThrownBy(() -> jdbc.sql("DELETE FROM users").update()).isInstanceOf(DataAccessException.class);
    }

    @Test
    void seedHasNoUsersNorDefaultCredentials() {
        // las migraciones no crean cuentas: el primer superadmin sale del bootstrap
        assertThat(jdbc.sql("SELECT count(*) FROM users WHERE email IN ('admin','admin@admin.com','admin@example.com')")
                .query(Long.class).single()).isZero();
    }
}
