package com.example.app.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.app.security.TotpService;
import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.json.JsonMapper;

class AuthFlowIT extends IntegrationTestBase {
    @Autowired JsonMapper json;
    @Autowired TotpService totp;

    MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder b, Object body) {
        return b.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
    }

    ResultActions login(Client c, String email, String password) throws Exception {
        return c.perform(json(post("/api/v1/auth/login"), Map.of("email", email, "password", password)));
    }

    // ---- sesiones y cookies ----

    @Test
    void loginSetsHardenedSessionCookie() throws Exception {
        var u = newUser("operador");
        Client c = client().csrf();
        MvcResult r = login(c, u.email(), PASSWORD).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OK")).andReturn();
        String setCookie = r.getResponse().getHeaders("Set-Cookie").stream()
                .filter(h -> h.startsWith("__Host-SESSION=")).findFirst().orElseThrow();
        assertThat(setCookie).contains("HttpOnly").contains("Secure").contains("SameSite=Lax").contains("Path=/")
                .doesNotContainIgnoringCase("Domain=");
        c.perform(get("/api/v1/auth/me")).andExpect(status().isOk()).andExpect(jsonPath("$.email").value(u.email()));
    }

    @Test
    void sessionIdIsRegeneratedOnLoginAndOldIdStopsWorking() throws Exception {
        var u = newUser("operador");
        Client c = client().csrf();
        login(c, u.email(), PASSWORD).andExpect(status().isOk());
        String first = c.session();
        login(c, u.email(), PASSWORD).andExpect(status().isOk());      // reingreso con sesion previa
        assertThat(c.session()).isNotEqualTo(first);

        Client attacker = client();
        attacker.cookies.put("__Host-SESSION", first);
        attacker.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutInvalidatesTheSessionOnTheServer() throws Exception {
        var u = newUser("operador");
        Client c = client().csrf();
        login(c, u.email(), PASSWORD).andExpect(status().isOk());
        String stolen = c.session();
        c.perform(post("/api/v1/auth/logout")).andExpect(status().isNoContent());

        Client replay = client();
        replay.cookies.put("__Host-SESSION", stolen);
        replay.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void csrfTokenIsRequiredForStateChangingRequests() throws Exception {
        var u = newUser("operador");
        mvc.perform(json(post("/api/v1/auth/login"), Map.of("email", u.email(), "password", PASSWORD)))
                .andExpect(status().isForbidden());
        // con cookie pero con cabecera distinta tambien se rechaza
        mvc.perform(json(post("/api/v1/auth/login"), Map.of("email", u.email(), "password", PASSWORD))
                        .cookie(new Cookie("XSRF-TOKEN", "abc")).header("X-XSRF-TOKEN", "otro"))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedRequestsGet401NotRedirects() throws Exception {
        mvc.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());
        mvc.perform(get("/ruta/inexistente")).andExpect(status().isUnauthorized());     // denegar por defecto
    }

    // ---- fuerza bruta y enumeracion ----

    @Test
    void failuresAreGenericAndIdenticalForUnknownUserAndWrongPassword() throws Exception {
        var u = newUser("operador");
        Client c = client().csrf();
        String a = login(c, u.email(), "mala contrasena larga").andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        String b = login(c, "noexiste@example.test", "mala contrasena larga").andExpect(status().isUnauthorized()).andReturn().getResponse().getContentAsString();
        assertThat(a).isEqualTo(b).isEqualTo("{\"code\":\"INVALID_CREDENTIALS\"}");
    }

    @Test
    void temporaryLockoutWithBackoffThenRecovers() throws Exception {
        var u = newUser("operador");
        Client c = client().csrf();
        for (int i = 0; i < 5; i++) login(c, u.email(), "mala contrasena " + i).andExpect(status().isUnauthorized());

        // aun con la clave correcta: bloqueado (y con la MISMA respuesta generica)
        login(c, u.email(), PASSWORD).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        var lockedUntil = jdbc.sql("SELECT locked_until FROM users WHERE id = :i").param("i", u.userId()).query(java.sql.Timestamp.class).single();
        assertThat(lockedUntil).isNotNull();

        // el bloqueo es TEMPORAL: al expirar vuelve a funcionar
        jdbc.sql("UPDATE users SET locked_until = now() - interval '1 second' WHERE id = :i").param("i", u.userId()).update();
        login(c, u.email(), PASSWORD).andExpect(status().isOk());
    }

    // ---- contrasenas ----

    @Test
    void transparentRehashWhenStoredParametersAreWeaker() throws Exception {
        var u = newUser("operador");
        String weak = new Argon2PasswordEncoder(16, 32, 1, 4096, 1).encode(PASSWORD);
        jdbc.sql("UPDATE users SET password_hash = :h WHERE id = :i").param("h", weak).param("i", u.userId()).update();
        login(client().csrf(), u.email(), PASSWORD).andExpect(status().isOk());
        String now = jdbc.sql("SELECT password_hash FROM users WHERE id = :i").param("i", u.userId()).query(String.class).single();
        assertThat(now).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
    }

    @Test
    void passwordChangeRevokesAllSessionsAndEnforcesPolicy() throws Exception {
        var u = newUser("operador");
        Client a = client().csrf();
        Client b = client().csrf();
        login(a, u.email(), PASSWORD).andExpect(status().isOk());
        login(b, u.email(), PASSWORD).andExpect(status().isOk());

        // politica: corta, comun/contexto, mala reautenticacion
        a.perform(json(post("/api/v1/auth/password"), Map.of("currentPassword", PASSWORD, "newPassword", "corta")))
                .andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$.violations[0]").value("PASSWORD_TOO_SHORT"));
        a.perform(json(post("/api/v1/auth/password"), Map.of("currentPassword", "incorrecta incorrecta", "newPassword", "otra frase suficientemente larga")))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("REAUTH_FAILED"));

        a.perform(json(post("/api/v1/auth/password"), Map.of("currentPassword", PASSWORD, "newPassword", "nueva frase secreta y distinta")))
                .andExpect(status().isNoContent());

        // TODAS las sesiones (incluida la de otro dispositivo) quedan revocadas
        a.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
        b.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
        // la clave anterior ya no sirve y la nueva si
        login(client().csrf(), u.email(), PASSWORD).andExpect(status().isUnauthorized());
        login(client().csrf(), u.email(), "nueva frase secreta y distinta").andExpect(status().isOk());
    }

    // ---- compuertas de estado de cuenta ----

    @Test
    void mustChangePasswordBlocksEverythingExceptChangePassword() throws Exception {
        var f = newUser(newTenant(), "solo_lectura", true);
        Client c = client().csrf();
        login(c, f.email(), PASSWORD).andExpect(status().isOk()).andExpect(jsonPath("$.mustChangePassword").value(true));
        c.perform(get("/api/v1/users")).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PASSWORD_CHANGE_REQUIRED"));
        c.perform(json(post("/api/v1/auth/password"), Map.of("currentPassword", PASSWORD, "newPassword", "frase nueva bien larga 2026")))
                .andExpect(status().isNoContent());
    }

    // ---- MFA ----

    @Test
    void privilegedRoleWithoutMfaIsGatedThenEnrollmentLoginAndRecoveryCodesWork() throws Exception {
        var f = newUser("admin");
        Client c = client().csrf();
        login(c, f.email(), PASSWORD).andExpect(status().isOk()).andExpect(jsonPath("$.mfaEnrollmentRequired").value(true));
        c.perform(get("/api/v1/users")).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("MFA_ENROLLMENT_REQUIRED"));

        // alta de MFA: exige reautenticacion con la contrasena
        c.perform(json(post("/api/v1/auth/mfa/setup"), Map.of("currentPassword", "no es la clave de nadie")))
                .andExpect(status().isForbidden());
        String body = c.perform(json(post("/api/v1/auth/mfa/setup"), Map.of("currentPassword", PASSWORD)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String secretB32 = json.readTree(body).get("secret").asString();
        byte[] secret = new Base32().decode(secretB32);
        // el secreto esta cifrado en reposo
        String stored = jdbc.sql("SELECT mfa_secret_enc FROM users WHERE id = :i").param("i", f.userId()).query(String.class).single();
        assertThat(stored).doesNotContain(secretB32);

        String code = totp.codeAt(secret, Instant.now());
        c.perform(json(post("/api/v1/auth/mfa/confirm"), Map.of("code", "000000".equals(code) ? "111111" : "000000")))
                .andExpect(status().isForbidden());
        String confirm = c.perform(json(post("/api/v1/auth/mfa/confirm"), Map.of("code", code)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        List<String> recovery = json.readTree(confirm).get("recoveryCodes").valueStream().map(n -> n.asString()).toList();
        assertThat(recovery).hasSize(10);
        // los codigos se guardan SOLO como hash
        assertThat(jdbc.sql("SELECT count(*) FROM recovery_codes WHERE user_id = :i AND code_hash = :c")
                .param("i", f.userId()).param("c", recovery.get(0)).query(Long.class).single()).isZero();

        c.perform(get("/api/v1/users")).andExpect(status().isOk());       // ya habilitado (con nuevo ID de sesion)
        c.perform(post("/api/v1/auth/logout")).andExpect(status().isNoContent());

        // login con MFA: la contrasena sola NO autentica
        Client c2 = client().csrf();
        login(c2, f.email(), PASSWORD).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("MFA_REQUIRED"));
        c2.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());
        // el mismo codigo TOTP (mismo paso) no se puede reutilizar
        c2.perform(json(post("/api/v1/auth/mfa/verify"), Map.of("code", code))).andExpect(status().isUnauthorized());
        String next = totp.codeAt(secret, Instant.now().plusSeconds(30));
        c2.perform(json(post("/api/v1/auth/mfa/verify"), Map.of("code", next))).andExpect(status().isOk());
        c2.perform(get("/api/v1/users")).andExpect(status().isOk());

        // codigo de recuperacion: sirve una sola vez
        Client c3 = client().csrf();
        login(c3, f.email(), PASSWORD).andExpect(jsonPath("$.status").value("MFA_REQUIRED"));
        c3.perform(json(post("/api/v1/auth/mfa/verify"), Map.of("code", recovery.get(0)))).andExpect(status().isOk());
        Client c4 = client().csrf();
        login(c4, f.email(), PASSWORD).andExpect(jsonPath("$.status").value("MFA_REQUIRED"));
        c4.perform(json(post("/api/v1/auth/mfa/verify"), Map.of("code", recovery.get(0)))).andExpect(status().isUnauthorized());
    }

    @Test
    void mfaPendingSessionIsLockedAfterTooManyWrongCodes() throws Exception {
        var f = newUser("admin");
        Client c = client().csrf();
        login(c, f.email(), PASSWORD).andExpect(status().isOk());
        String body = c.perform(json(post("/api/v1/auth/mfa/setup"), Map.of("currentPassword", PASSWORD))).andReturn().getResponse().getContentAsString();
        byte[] secret = new Base32().decode(json.readTree(body).get("secret").asString());
        c.perform(json(post("/api/v1/auth/mfa/confirm"), Map.of("code", totp.codeAt(secret, Instant.now())))).andExpect(status().isOk());
        c.perform(post("/api/v1/auth/logout"));

        Client c2 = client().csrf();
        login(c2, f.email(), PASSWORD).andExpect(jsonPath("$.status").value("MFA_REQUIRED"));
        for (int i = 0; i < 5; i++) {
            c2.perform(json(post("/api/v1/auth/mfa/verify"), Map.of("code", "00000" + i))).andExpect(status().isUnauthorized());
        }
        // con el codigo correcto ya no entra: hay que volver a empezar con la contrasena
        c2.perform(json(post("/api/v1/auth/mfa/verify"), Map.of("code", totp.codeAt(secret, Instant.now().plusSeconds(30)))))
                .andExpect(status().isUnauthorized());
    }
}
