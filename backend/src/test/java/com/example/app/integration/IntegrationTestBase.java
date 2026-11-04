package com.example.app.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.example.app.common.RateLimiter;
import com.example.app.security.AppUserDetails;
import com.example.app.security.PasswordHasher;
import com.example.app.user.UserRepository;
import jakarta.servlet.http.Cookie;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Pruebas de integracion contra PostgreSQL real (docker compose local o servicio Postgres en CI). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
abstract class IntegrationTestBase {
    static final String PASSWORD = "correcta caballo bateria grapa";

    @Autowired protected MockMvc mvc;
    @Autowired protected UserRepository users;
    @Autowired protected PasswordHasher hasher;
    @Autowired protected JdbcClient jdbc;
    @Autowired protected RateLimiter limiter;

    @BeforeEach
    void resetLimiter() {
        limiter.reset();
    }

    protected record Fixture(UUID tenantId, UUID userId, String email) {}

    protected UUID newTenant() {
        return users.insertTenant("Comercio " + UUID.randomUUID());
    }

    protected Fixture newUser(UUID tenantId, String role, boolean mustChange) {
        String email = "u" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";
        UUID id = users.insert(tenantId, email, "Usuario Prueba", hasher.hash(PASSWORD), mustChange, null);
        users.replaceRoles(id, tenantId, Set.of(role), null);
        return new Fixture(tenantId, id, email);
    }

    protected Fixture newUser(String role) {
        return newUser(newTenant(), role, false);
    }

    /** Principal en memoria (sin sesion) con los permisos reales del rol en BD. */
    protected AppUserDetails principal(Fixture f, String role, boolean mfaEnabled) {
        boolean mfaRequired = Boolean.TRUE.equals(jdbc.sql("SELECT mfa_required FROM roles WHERE name = :n")
                .param("n", role).query(Boolean.class).single());
        return new AppUserDetails(f.userId(), f.tenantId(), f.email(), "Usuario Prueba", Set.of(role),
                users.permissionsOfRole(role), mfaEnabled, mfaRequired, false);
    }

    /** Cliente con jar de cookies y manejo del token CSRF, como lo haria la SPA. */
    protected Client client() {
        return new Client();
    }

    protected class Client {
        final Map<String, String> cookies = new LinkedHashMap<>();

        ResultActions perform(MockHttpServletRequestBuilder b) throws Exception {
            cookies.forEach((k, v) -> b.cookie(new Cookie(k, v)));
            String xsrf = cookies.get("XSRF-TOKEN");
            if (xsrf != null) b.header("X-XSRF-TOKEN", xsrf);
            ResultActions r = mvc.perform(b);
            absorb(r.andReturn().getResponse());
            return r;
        }

        void absorb(MockHttpServletResponse res) {
            for (String h : res.getHeaders("Set-Cookie")) {
                String[] first = h.split(";", 2)[0].split("=", 2);
                String value = first.length > 1 ? first[1] : "";
                if (value.isEmpty() || h.toLowerCase().contains("max-age=0")) cookies.remove(first[0]);
                else cookies.put(first[0], value);
            }
        }

        Client csrf() throws Exception {
            perform(get("/api/v1/auth/csrf"));
            return this;
        }

        String session() {
            return cookies.get("__Host-SESSION");
        }

        boolean has(HttpMethod m) { return true; }
    }
}
