package com.example.app.config;

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.SessionIdGenerator;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Cookie de sesion y generacion de IDs, declarados de forma EXPLICITA (no dependen de propiedades que cambian entre versiones):
 *  - cookie __Host-SESSION: Secure, HttpOnly, SameSite=Lax, Path=/, sin Domain;
 *  - ID de sesion de 256 bits (CSPRNG). El UUID por defecto solo aporta 122 bits y ASVS pide >= 128.
 */
@Configuration
public class SessionConfig {

    @Bean
    CookieSerializer cookieSerializer(AppProperties props) {
        var s = new DefaultCookieSerializer();
        s.setCookieName("__Host-SESSION");
        s.setUseSecureCookie(props.security().secureCookies());
        s.setUseHttpOnlyCookie(true);
        s.setSameSite("Lax");
        s.setCookiePath("/");
        s.setDomainName(null);
        s.setUseBase64Encoding(true);
        return s;
    }

    @Bean
    SessionRepositoryCustomizer<JdbcIndexedSessionRepository> sessionIdCustomizer() {
        SecureRandom random = new SecureRandom();
        SessionIdGenerator generator = () -> {
            byte[] id = new byte[32];
            random.nextBytes(id);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(id);
        };
        return repo -> repo.setSessionIdGenerator(generator);
    }
}
