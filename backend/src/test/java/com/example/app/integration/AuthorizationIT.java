package com.example.app.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.app.security.AppUserDetails;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** Matriz rol x endpoint, anti-IDOR, mass assignment, anti-escalada y proteccion del ultimo superadmin. */
class AuthorizationIT extends IntegrationTestBase {

    RequestPostProcessor as(AppUserDetails p) {
        return authentication(UsernamePasswordAuthenticationToken.authenticated(p, null, p.getAuthorities()));
    }

    /** Token CSRF real (cookie + cabecera iguales). No se usa csrf() de spring-security-test: muta el filtro global. */
    RequestPostProcessor csrfOk() {
        return request -> {
            request.setCookies(new jakarta.servlet.http.Cookie("XSRF-TOKEN", "token-de-prueba"));
            request.addHeader("X-XSRF-TOKEN", "token-de-prueba");
            return request;
        };
    }

    AppUserDetails actor(String role) {
        var f = newUser(role);
        return principal(f, role, true);
    }

    // rol, GET /users, POST /users, PUT /users/{id}/roles, POST /users/{id}/disable
    static Stream<Arguments> matrix() {
        return Stream.of(
                Arguments.of("superadmin",   200, 201, 200, 204),
                Arguments.of("admin",        200, 201, 200, 204),
                Arguments.of("gestor",       200, 403, 403, 403),
                Arguments.of("operador",     403, 403, 403, 403),
                Arguments.of("solo_lectura", 200, 403, 403, 403));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("matrix")
    void roleByEndpointMatrix(String role, int list, int create, int assign, int disable) throws Exception {
        AppUserDetails me = actor(role);
        var target = newUser(me.tenantId(), "solo_lectura", false);
        var target2 = newUser(me.tenantId(), "solo_lectura", false);

        mvc.perform(get("/api/v1/users").with(as(me))).andExpect(status().is(list));
        mvc.perform(post("/api/v1/users").with(as(me)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"n" + UUID.randomUUID() + "@example.test\",\"fullName\":\"Nuevo\",\"roles\":[\"operador\"]}"))
                .andExpect(status().is(create));
        mvc.perform(put("/api/v1/users/" + target.userId() + "/roles").with(as(me)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"roles\":[\"operador\"]}")).andExpect(status().is(assign));
        mvc.perform(post("/api/v1/users/" + target2.userId() + "/disable").with(as(me)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"reason\":\"baja de prueba\"}")).andExpect(status().is(disable));
    }

    @Test
    void anonymousIsDeniedEverywhere() throws Exception {
        mvc.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/users/" + UUID.randomUUID())).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/users").with(csrfOk()).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isUnauthorized());
    }

    @Test
    void idorUsersOfAnotherTenantAreInvisibleAs404() throws Exception {
        AppUserDetails adminA = actor("admin");
        var victimB = newUser(newTenant(), "operador", false);
        mvc.perform(get("/api/v1/users/" + victimB.userId()).with(as(adminA))).andExpect(status().isNotFound());
        mvc.perform(put("/api/v1/users/" + victimB.userId() + "/roles").with(as(adminA)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"solo_lectura\"]}")).andExpect(status().isNotFound());
        mvc.perform(post("/api/v1/users/" + victimB.userId() + "/disable").with(as(adminA)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"x\"}")).andExpect(status().isNotFound());
        // y el listado solo contiene usuarios de SU comercio
        String body = mvc.perform(get("/api/v1/users?size=100").with(as(adminA))).andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain(victimB.email());
        // la victima sigue intacta
        assertThat(users.findById(victimB.userId()).orElseThrow().active()).isTrue();
    }

    @Test
    void massAssignmentOfSensitiveFieldsIsRejected() throws Exception {
        AppUserDetails admin = actor("admin");
        UUID otherTenant = newTenant();
        for (String extra : new String[]{"\"tenantId\":\"" + otherTenant + "\"", "\"status\":\"ACTIVE\"", "\"isAdmin\":true",
                "\"mustChangePassword\":false", "\"passwordHash\":\"x\""}) {
            mvc.perform(post("/api/v1/users").with(as(admin)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                    .content("{\"email\":\"m" + UUID.randomUUID() + "@example.test\",\"fullName\":\"X\",\"roles\":[\"operador\"]," + extra + "}"))
                    .andExpect(status().isBadRequest());
        }
    }

    @Test
    void createdUserLivesInTheActorsTenantAndMustChangeTheOneTimePassword() throws Exception {
        AppUserDetails admin = actor("admin");
        String body = mvc.perform(post("/api/v1/users").with(as(admin)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"Nuevo" + UUID.randomUUID() + "@Example.test\",\"fullName\":\"Nuevo\",\"roles\":[\"operador\"]}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.temporaryPassword").isString())
                .andReturn().getResponse().getContentAsString();
        UUID id = UUID.fromString(new tools.jackson.databind.json.JsonMapper().readTree(body).get("user").get("id").asString());
        var created = users.findById(id).orElseThrow();
        assertThat(created.tenantId()).isEqualTo(admin.tenantId());
        assertThat(created.mustChangePassword()).isTrue();
        assertThat(created.email()).isEqualTo(created.email().toLowerCase());
        assertThat(created.passwordHash()).startsWith("$argon2id$");
    }

    @Test
    void noPrivilegeEscalation() throws Exception {
        AppUserDetails admin = actor("admin");
        var target = newUser(admin.tenantId(), "operador", false);
        // admin NO posee todos los permisos de superadmin (le falta tenant:update) => no puede otorgarlo
        mvc.perform(put("/api/v1/users/" + target.userId() + "/roles").with(as(admin)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"superadmin\"]}")).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/users").with(as(admin)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"e" + UUID.randomUUID() + "@example.test\",\"fullName\":\"X\",\"roles\":[\"superadmin\"]}")).andExpect(status().isForbidden());
        // tampoco puede quitarle el rol a un superadmin ni desactivarlo
        var sa = newUser(admin.tenantId(), "superadmin", false);
        mvc.perform(put("/api/v1/users/" + sa.userId() + "/roles").with(as(admin)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"operador\"]}")).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/users/" + sa.userId() + "/disable").with(as(admin)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"x\"}")).andExpect(status().isForbidden());
        assertThat(users.roleNames(target.userId())).containsExactly("operador");
        assertThat(users.roleNames(sa.userId())).containsExactly("superadmin");
        // rol inexistente
        mvc.perform(put("/api/v1/users/" + target.userId() + "/roles").with(as(admin)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"dios\"]}")).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void nobodyEditsTheirOwnRolesOrDisablesThemselves() throws Exception {
        var f = newUser("superadmin");
        AppUserDetails me = principal(f, "superadmin", true);
        mvc.perform(put("/api/v1/users/" + f.userId() + "/roles").with(as(me)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"operador\"]}")).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/users/" + f.userId() + "/disable").with(as(me)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"x\"}")).andExpect(status().isForbidden());
    }

    @Test
    void lastSuperadminIsProtected() throws Exception {
        UUID tenant = newTenant();
        var onlySuper = newUser(tenant, "superadmin", false);
        // actor superadmin sin fila activa en BD (p. ej. sesion antigua): el objetivo es el UNICO superadmin activo
        var ghost = new AppUserDetails(UUID.randomUUID(), tenant, "g@example.test", "Ghost", java.util.Set.of("superadmin"),
                users.permissionsOfRole("superadmin"), true, true, false);
        mvc.perform(put("/api/v1/users/" + onlySuper.userId() + "/roles").with(as(ghost)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"operador\"]}")).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("LAST_SUPERADMIN"));
        mvc.perform(post("/api/v1/users/" + onlySuper.userId() + "/disable").with(as(ghost)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"x\"}")).andExpect(status().isConflict());
        // con un segundo superadmin si se puede degradar a uno
        newUser(tenant, "superadmin", false);
        mvc.perform(put("/api/v1/users/" + onlySuper.userId() + "/roles").with(as(ghost)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"operador\"]}")).andExpect(status().isOk());
    }

    @Test
    void roleChangeAndDisableRevokeTheTargetsSessionsAndAreAudited() throws Exception {
        UUID tenant = newTenant();
        var victim = newUser(tenant, "operador", false);
        Client v = client().csrf();
        v.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + victim.email() + "\",\"password\":\"" + PASSWORD + "\"}")).andExpect(status().isOk());
        v.perform(get("/api/v1/auth/me")).andExpect(status().isOk());

        AppUserDetails admin = principal(newUser(tenant, "admin", false), "admin", true);
        mvc.perform(post("/api/v1/users/" + victim.userId() + "/disable").with(as(admin)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"reason\":\"fin de contrato\"}")).andExpect(status().isNoContent());

        v.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());               // sesion revocada
        v.csrf().perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)    // y no puede reingresar
                .content("{\"email\":\"" + victim.email() + "\",\"password\":\"" + PASSWORD + "\"}")).andExpect(status().isUnauthorized());
        long audited = jdbc.sql("SELECT count(*) FROM audit_log WHERE event = 'user.disabled' AND resource = :r AND tenant_id = :t")
                .param("r", "user:" + victim.userId()).param("t", tenant).query(Long.class).single();
        assertThat(audited).isEqualTo(1);
    }

    @Test
    void roleChangeAuditKeepsOldAndNewValues() throws Exception {
        UUID tenant = newTenant();
        var target = newUser(tenant, "operador", false);
        AppUserDetails admin = principal(newUser(tenant, "admin", false), "admin", true);
        mvc.perform(put("/api/v1/users/" + target.userId() + "/roles").with(as(admin)).with(csrfOk())
                .contentType(MediaType.APPLICATION_JSON).content("{\"roles\":[\"gestor\"]}")).andExpect(status().isOk());
        String details = jdbc.sql("SELECT details::text FROM audit_log WHERE event = 'user.roles.changed' AND resource = :r")
                .param("r", "user:" + target.userId()).query(String.class).single();
        assertThat(details).contains("operador").contains("gestor");
    }

    @Test
    void validationErrorsAreGenericAndNeverEchoInput() throws Exception {
        AppUserDetails admin = actor("admin");
        String body = mvc.perform(post("/api/v1/users").with(as(admin)).with(csrfOk()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"no-es-email\",\"fullName\":\"\",\"roles\":[]}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("VALIDATION_FAILED")).andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("no-es-email");
        assertThat(body).contains("requestId");
    }
}
