package com.example.app.config;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.common.RequestIdFilter;
import com.example.app.security.AbsoluteTimeoutFilter;
import com.example.app.security.AuthenticatedRequestFilter;
import java.util.List;
import java.util.Map;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Cadena de seguridad. Principios: DENEGAR POR DEFECTO (cualquier ruta no listada exige autenticacion y,
 * por el test ArchUnit, todo handler exige un permiso), CSRF activo, CORS con lista blanca, cabeceras de seguridad.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AppProperties props, AuditService audit) throws Exception {
        var csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();   // la SPA debe poder leerla para reenviarla en la cabecera
        csrfRepo.setCookieCustomizer(c -> c.secure(props.security().secureCookies()).sameSite("Lax").path("/"));

        http
            .csrf(c -> c.csrfTokenRepository(csrfRepo).csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .cors(Customizer.withDefaults())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation(f -> f.changeSessionId()))
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a
                    .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf").permitAll()
                    .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/mfa/verify").permitAll()
                    .anyRequest().authenticated())                       // denegar por defecto
            .exceptionHandling(e -> e
                    .authenticationEntryPoint((req, res, ex) -> {
                        res.setStatus(401);
                        res.setContentType("application/json");
                        res.getWriter().write("{\"code\":\"UNAUTHENTICATED\",\"requestId\":\"" + MDC.get(RequestIdFilter.MDC_KEY) + "\"}");
                    })
                    .accessDeniedHandler((req, res, ex) -> {
                        audit.record("authz.denied", Result.DENIED, "endpoint", "access",
                                ex.getClass().getSimpleName(), Map.of());
                        res.setStatus(403);
                        res.setContentType("application/json");
                        res.getWriter().write("{\"code\":\"FORBIDDEN\",\"requestId\":\"" + MDC.get(RequestIdFilter.MDC_KEY) + "\"}");
                    }))
            .headers(h -> h
                    .contentSecurityPolicy(c -> c.policyDirectives("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"))
                    .httpStrictTransportSecurity(s -> s.maxAgeInSeconds(31536000).includeSubDomains(true))
                    .frameOptions(f -> f.deny())
                    .contentTypeOptions(Customizer.withDefaults())
                    .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                    .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()"))
                    .addHeaderWriter(new StaticHeadersWriter("Cross-Origin-Opener-Policy", "same-origin"))
                    .addHeaderWriter(new StaticHeadersWriter("Cross-Origin-Resource-Policy", "same-origin")))
            .addFilterBefore(new AbsoluteTimeoutFilter(props.security().session().absolute()), AuthorizationFilter.class)
            .addFilterBefore(new AuthenticatedRequestFilter(), AuthorizationFilter.class);
        return http.build();
    }

    /** CORS: solo los origenes de la lista blanca explicita. Vacio => solo mismo origen (lo normal con proxy/nginx). */
    @Bean
    CorsConfigurationSource corsConfigurationSource(AppProperties props) {
        var cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(props.security().corsAllowedOrigins());
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE"));
        cfg.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN", "X-Request-Id"));
        cfg.setExposedHeaders(List.of("X-Request-Id", "Retry-After"));
        cfg.setAllowCredentials(!props.security().corsAllowedOrigins().isEmpty());
        cfg.setMaxAge(600L);
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", cfg);
        return source;
    }
}
