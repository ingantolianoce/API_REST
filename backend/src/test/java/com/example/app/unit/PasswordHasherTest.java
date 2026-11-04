package com.example.app.unit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.app.config.AppProperties;
import com.example.app.security.PasswordHasher;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

class PasswordHasherTest {
    private final PasswordHasher hasher = new PasswordHasher(PasswordPolicyTest.props());

    @Test
    void usesArgon2idWithPhcFormatAndMinimumOwaspParameters() {
        String h = hasher.hash("una contrasena larga y unica");
        assertThat(h).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(hasher.matches("una contrasena larga y unica", h)).isTrue();
        assertThat(hasher.matches("otra", h)).isFalse();
        assertThat(hasher.needsRehash(h)).isFalse();
    }

    @Test
    void saltIsUniquePerHash() {
        assertThat(hasher.hash("misma")).isNotEqualTo(hasher.hash("misma"));
    }

    @Test
    void detectsWeakerParametersAndForeignFormatsForTransparentRehash() {
        String weak = new Argon2PasswordEncoder(16, 32, 1, 4096, 1).encode("x");
        assertThat(hasher.needsRehash(weak)).isTrue();
        assertThat(hasher.needsRehash("$2a$10$abcdefghijklmnopqrstuv")).isTrue();     // bcrypt heredado
        assertThat(hasher.needsRehash(null)).isTrue();
    }

    @Test
    void failsClosedOnGarbageAndOversizedInput() {
        assertThat(hasher.matches("x", "no-es-un-hash")).isFalse();
        assertThat(hasher.matches(null, hasher.hash("x"))).isFalse();
        assertThat(hasher.matches("x".repeat(1000), hasher.hash("x"))).isFalse();
        hasher.burnDecoy("cualquiera");   // no lanza
    }
}
