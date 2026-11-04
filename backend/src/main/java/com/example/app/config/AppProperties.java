package com.example.app.config;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Configuracion tipada. Sin valores por defecto para secretos. */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        @DefaultValue Security security,
        @DefaultValue Crypto crypto,
        @DefaultValue Bootstrap bootstrap) {

    public record Security(
            @DefaultValue("true") boolean secureCookies,
            @DefaultValue List<String> corsAllowedOrigins,
            @DefaultValue("1048576") long maxBodyBytes,
            @DefaultValue Login login,
            @DefaultValue Password password,
            @DefaultValue Argon2 argon2,
            @DefaultValue Session session) {}

    public record Login(
            @DefaultValue("30") int ipLimitPerMinute,
            @DefaultValue("10") int accountLimitPerMinute,
            @DefaultValue("5") int maxFailedAttempts,
            @DefaultValue("30") int lockBaseSeconds,
            @DefaultValue("900") int lockMaxSeconds) {}

    public record Password(
            @DefaultValue("15") int minLength,
            @DefaultValue("128") int maxLength,
            @DefaultValue("true") boolean hibpEnabled,
            @DefaultValue("false") boolean hibpFailClosed) {}

    public record Argon2(
            @DefaultValue("19456") int memoryKib,
            @DefaultValue("2") int iterations,
            @DefaultValue("1") int parallelism,
            @DefaultValue("8") int maxConcurrentHashes) {}

    public record Session(
            @DefaultValue("2h") Duration idleStandard,
            @DefaultValue("20m") Duration idlePrivileged,
            @DefaultValue("10h") Duration absolute) {}

    public record Crypto(String key) {}

    public record Bootstrap(
            @DefaultValue("false") boolean enabled,
            @DefaultValue("") String adminEmail,
            @DefaultValue("") String tenantName,
            @DefaultValue("") String passwordFile) {}
}
