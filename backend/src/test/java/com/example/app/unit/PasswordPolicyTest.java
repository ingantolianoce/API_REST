package com.example.app.unit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.app.config.AppProperties;
import com.example.app.security.PasswordPolicy;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class PasswordPolicyTest {
    private final boolean[] breachedAnswer = {false};
    private final PasswordPolicy policy = new PasswordPolicy(props(), (p, failClosed) -> breachedAnswer[0]);

    static AppProperties props() {
        return new AppProperties(
                new AppProperties.Security(true, List.of(), 1_000_000,
                        new AppProperties.Login(30, 10, 5, 30, 900),
                        new AppProperties.Password(15, 128, true, false),
                        new AppProperties.Argon2(19456, 2, 1, 8),
                        new AppProperties.Session(Duration.ofHours(2), Duration.ofMinutes(20), Duration.ofHours(10))),
                new AppProperties.Crypto("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
                new AppProperties.Bootstrap(false, "", "", ""));
    }

    @Test
    void rejectsShortPasswords() {
        assertThat(policy.validate("corta1234", List.of())).contains("PASSWORD_TOO_SHORT");
    }

    @Test
    void acceptsLongPassphraseWithSpacesAndUnicodeAndNoCompositionRules() {
        assertThat(policy.validate("mi perro come ñandú en la plaza", List.of())).isEmpty();
        assertThat(policy.validate("aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb", List.of())).isEmpty();   // sin reglas de composicion
    }

    @Test
    void countsCodePointsNotUtf16Units() {
        // 15 emojis = 15 puntos de codigo (30 unidades UTF-16): cumple el minimo de 15
        assertThat(policy.validate("😀".repeat(15), List.of())).doesNotContain("PASSWORD_TOO_SHORT");
        assertThat(policy.validate("😀".repeat(14), List.of())).contains("PASSWORD_TOO_SHORT");
    }

    @Test
    void rejectsTooLong() {
        assertThat(policy.validate("x".repeat(129), List.of())).contains("PASSWORD_TOO_LONG");
        assertThat(policy.validate("x".repeat(128), List.of())).doesNotContain("PASSWORD_TOO_LONG");
    }

    @Test
    void blocklistRejectsCommonPasswordsCaseInsensitive() {
        // Con minimo 15 todas las comunes ya fallan por longitud; el bloqueo importa cuando se baja a 8 (MFA para todos).
        var p = props();
        var relaxed = new AppProperties(new AppProperties.Security(true, List.of(), 1_000_000, p.security().login(),
                new AppProperties.Password(8, 128, false, false), p.security().argon2(), p.security().session()),
                p.crypto(), p.bootstrap());
        var policy8 = new PasswordPolicy(relaxed, (pw, f) -> false);
        assertThat(policy8.validate("Password123", List.of())).contains("PASSWORD_COMMON");
        assertThat(policy8.validate("CHANGEME123", List.of())).contains("PASSWORD_COMMON");
        assertThat(policy8.validate("trompo-azul-77", List.of())).isEmpty();
    }

    @Test
    void rejectsContextWords() {
        assertThat(policy.validate("juanperez-2026-secreto", List.of("juanperez", "Juan"))).contains("PASSWORD_CONTAINS_CONTEXT");
    }

    @Test
    void rejectsBreachedPasswords() {
        breachedAnswer[0] = true;
        assertThat(policy.validate("una frase larga cualquiera", List.of())).contains("PASSWORD_BREACHED");
    }
}
