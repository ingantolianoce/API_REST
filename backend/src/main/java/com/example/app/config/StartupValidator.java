package com.example.app.config;

import jakarta.annotation.PostConstruct;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * Falla al arrancar (cerrado) si la configuracion de seguridad es insegura.
 * Es mejor no iniciar que iniciar debilitado.
 */
@Component
public class StartupValidator {

    private final AppProperties props;

    public StartupValidator(AppProperties props) {
        this.props = props;
    }

    @PostConstruct
    void validate() {
        var s = props.security();
        var a = s.argon2();
        // Minimos OWASP Password Storage: m=19456 KiB, t=2, p=1
        require(a.memoryKib() >= 19456 && a.iterations() >= 2 && a.parallelism() >= 1,
                "Argon2id por debajo del minimo OWASP (m>=19456 KiB, t>=2, p>=1)");
        require(a.maxConcurrentHashes() >= 1, "app.security.argon2.max-concurrent-hashes debe ser >= 1");
        require(s.password().minLength() >= 15,
                "app.security.password.min-length debe ser >= 15 (bajar a 8 exige MFA para TODOS; decision documentada en SECURITY_DECISIONS.md)");
        require(s.password().maxLength() >= 64, "app.security.password.max-length debe ser >= 64");
        require(s.secureCookies(), "app.security.secure-cookies debe ser true (cookies Secure)");
        for (String origin : s.corsAllowedOrigins()) {
            require(!origin.contains("*"), "CORS: no se permiten comodines en allowed-origins");
        }
        require(s.session().absolute().compareTo(s.session().idlePrivileged()) > 0,
                "El timeout absoluto debe ser mayor que el de inactividad");
        byte[] key;
        try {
            key = Base64.getDecoder().decode(props.crypto().key() == null ? "" : props.crypto().key());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("app.crypto.key no es base64 valido");
        }
        require(key.length == 32, "app.crypto.key debe ser base64 de exactamente 32 bytes (openssl rand -base64 32)");
        var b = props.bootstrap();
        if (b.enabled()) {
            require(!b.adminEmail().isBlank() && !b.tenantName().isBlank() && !b.passwordFile().isBlank(),
                    "Bootstrap activo: admin-email, tenant-name y password-file son obligatorios");
        }
    }

    private static void require(boolean ok, String message) {
        if (!ok) {
            throw new IllegalStateException("Configuracion insegura: " + message);
        }
    }
}
