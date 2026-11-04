package com.example.app.security;

import com.example.app.config.AppProperties;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

/**
 * Politica de contrasenas (NIST SP 800-63B Rev. 4): longitud minima/maxima, sin reglas de composicion,
 * sin expiracion periodica, lista de bloqueo (comunes + contexto + filtradas en brechas).
 * Devuelve codigos de violacion para explicarle al usuario por que se rechazo.
 */
@Component
public class PasswordPolicy {
    private final AppProperties.Password cfg;
    private final BreachedPasswordChecker breached;
    private final Set<String> common = new HashSet<>();

    public PasswordPolicy(AppProperties props, BreachedPasswordChecker breached) {
        this.cfg = props.security().password();
        this.breached = breached;
        try (var r = new BufferedReader(new InputStreamReader(
                new ClassPathResource("common-passwords.txt").getInputStream(), StandardCharsets.UTF_8))) {
            r.lines().map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#"))
                    .forEach(l -> common.add(normalize(l)));
        } catch (IOException e) {
            throw new IllegalStateException("No se pudo cargar la lista de contrasenas comunes", e);
        }
    }

    /** @param contextWords palabras del contexto (email, nombre, nombre del sistema) que no pueden formar parte. */
    public List<String> validate(String password, List<String> contextWords) {
        List<String> violations = new ArrayList<>();
        if (password == null) return List.of("PASSWORD_TOO_SHORT");
        int length = password.codePointCount(0, password.length());   // cada punto de codigo cuenta como 1
        if (length < cfg.minLength()) violations.add("PASSWORD_TOO_SHORT");
        if (length > cfg.maxLength()) violations.add("PASSWORD_TOO_LONG");
        if (!violations.isEmpty()) return violations;                  // no sigue evaluando entradas fuera de rango

        String n = normalize(password);
        if (common.contains(n)) violations.add("PASSWORD_COMMON");
        for (String w : contextWords) {
            String cw = normalize(w == null ? "" : w);
            if (cw.length() >= 4 && n.contains(cw)) {
                violations.add("PASSWORD_CONTAINS_CONTEXT");
                break;
            }
        }
        if (violations.isEmpty() && cfg.hibpEnabled() && breached.isBreached(password, cfg.hibpFailClosed())) {
            violations.add("PASSWORD_BREACHED");
        }
        return violations;
    }

    private static String normalize(String s) {
        return Normalizer.normalize(s, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }
}
