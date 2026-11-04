package com.example.app.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.app.security.FieldEncryptor;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class FieldEncryptorTest {
    private final FieldEncryptor enc = new FieldEncryptor(PasswordPolicyTest.props());

    @Test
    void roundTrip() {
        String c = enc.encrypt("secreto".getBytes(StandardCharsets.UTF_8), "user:1");
        assertThat(new String(enc.decrypt(c, "user:1"), StandardCharsets.UTF_8)).isEqualTo("secreto");
    }

    @Test
    void ivIsRandomPerEncryption() {
        assertThat(enc.encrypt(new byte[]{1}, "a")).isNotEqualTo(enc.encrypt(new byte[]{1}, "a"));
    }

    @Test
    void aadBindsCiphertextToItsRow() {
        String c = enc.encrypt(new byte[]{1, 2, 3}, "user:1");
        assertThatThrownBy(() -> enc.decrypt(c, "user:2")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void tamperingIsDetected() {
        byte[] raw = Base64.getDecoder().decode(enc.encrypt(new byte[]{1, 2, 3}, "a"));
        raw[raw.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThatThrownBy(() -> enc.decrypt(tampered, "a")).isInstanceOf(IllegalStateException.class);
    }
}
