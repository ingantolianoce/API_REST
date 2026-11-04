package com.example.app.security;

import com.example.app.config.AppProperties;
import java.security.SecureRandom;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Argon2id (OWASP: m=19456 KiB, t=2, p=1 como minimo). Formato PHC autodescriptivo.
 * - Rehash transparente: needsRehash() compara los parametros del hash guardado con los actuales.
 * - Hash senuelo para igualar tiempos cuando el usuario no existe.
 * - Semaforo que limita el hashing concurrente (evita DoS por CPU/memoria).
 */
@Component
public class PasswordHasher {
    private static final Pattern PHC = Pattern.compile("^\\$argon2id\\$v=19\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$.+");
    private static final int MAX_INPUT = 256;

    private final Argon2PasswordEncoder encoder;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final Semaphore permits;
    private final String decoyHash;

    public PasswordHasher(AppProperties props) {
        var a = props.security().argon2();
        this.memory = a.memoryKib();
        this.iterations = a.iterations();
        this.parallelism = a.parallelism();
        this.encoder = new Argon2PasswordEncoder(16, 32, parallelism, memory, iterations);
        this.permits = new Semaphore(a.maxConcurrentHashes());
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        this.decoyHash = encoder.encode(java.util.HexFormat.of().formatHex(random));
    }

    public String hash(String raw) {
        return guarded(() -> encoder.encode(raw));
    }

    /** Compara en tiempo constante (lo hace la libreria). Cualquier error => false (falla cerrado). */
    public boolean matches(String raw, String hash) {
        if (raw == null || hash == null || raw.length() > MAX_INPUT) return false;
        try {
            return guarded(() -> encoder.matches(raw, hash));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Consume el mismo tiempo que una verificacion real (usuario inexistente, bloqueado o desactivado). */
    public void burnDecoy(String raw) {
        if (raw == null || raw.length() > MAX_INPUT) return;
        try {
            guarded(() -> encoder.matches(raw, decoyHash));
        } catch (RuntimeException ignored) {
            // nada que hacer: solo igualamos el tiempo
        }
    }

    public boolean needsRehash(String hash) {
        Matcher m = PHC.matcher(hash == null ? "" : hash);
        if (!m.matches()) return true;
        return Integer.parseInt(m.group(1)) < memory
                || Integer.parseInt(m.group(2)) < iterations
                || Integer.parseInt(m.group(3)) < parallelism;
    }

    private <T> T guarded(java.util.function.Supplier<T> op) {
        try {
            permits.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrumpido");
        }
        try {
            return op.get();
        } finally {
            permits.release();
        }
    }
}
