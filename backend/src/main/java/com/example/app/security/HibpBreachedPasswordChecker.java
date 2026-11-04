package com.example.app.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Pwned Passwords con k-anonimato: se envian SOLO los primeros 5 caracteres del SHA-1 (el protocolo de HIBP lo exige;
 * SHA-1 aqui NO es un mecanismo de seguridad propio). La contrasena nunca sale del servidor.
 */
@Component
public class HibpBreachedPasswordChecker implements BreachedPasswordChecker {
    private static final Logger log = LoggerFactory.getLogger(HibpBreachedPasswordChecker.class);
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build();

    @Override
    public boolean isBreached(String password, boolean failClosed) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8));
            String hex = HexFormat.of().withUpperCase().formatHex(digest);
            String prefix = hex.substring(0, 5);
            String suffix = hex.substring(5);
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://api.pwnedpasswords.com/range/" + prefix))
                    .timeout(Duration.ofSeconds(3)).header("Add-Padding", "true").GET().build();
            HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) throw new IllegalStateException("HIBP status " + res.statusCode());
            return res.body().lines().anyMatch(l -> {
                String[] parts = l.strip().split(":");
                return parts.length == 2 && parts[0].equalsIgnoreCase(suffix) && !"0".equals(parts[1].strip());
            });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failClosed;
        } catch (Exception e) {
            log.warn("Consulta HIBP no disponible; fail-closed={}", failClosed);
            return failClosed;
        }
    }
}
