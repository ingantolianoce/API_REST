package com.example.app.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

@TestPropertySource(properties = "app.security.login.account-limit-per-minute=3")
class RateLimitIT extends IntegrationTestBase {

    @Test
    void loginIsRateLimitedPerAccountWith429AndRetryAfter() throws Exception {
        var u = newUser("operador");
        Client c = client().csrf();
        String body = "{\"email\":\"" + u.email() + "\",\"password\":\"incorrecta incorrecta\"}";
        for (int i = 0; i < 3; i++) {
            c.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isUnauthorized());
        }
        c.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isTooManyRequests()).andExpect(header().exists("Retry-After"));
        // la cuenta correcta tambien queda limitada mientras dure la ventana (no se puede probar sin limite)
        c.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + u.email() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isTooManyRequests());
    }
}
