package com.example.app.unit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.app.security.TotpService;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class TotpServiceTest {
    private final TotpService totp = new TotpService();

    @Test
    void acceptsCodeWithinWindowAndReturnsTimeStep() {
        byte[] secret = totp.newSecret();
        Instant now = Instant.parse("2026-11-04T12:00:10Z");
        var step = totp.verify(secret, totp.codeAt(secret, now), now);
        assertThat(step).isPresent();
        assertThat(step.getAsLong()).isEqualTo(now.getEpochSecond() / 30);
        // un paso antes y uno despues siguen siendo validos (+-1)
        assertThat(totp.verify(secret, totp.codeAt(secret, now.minusSeconds(30)), now)).isPresent();
        assertThat(totp.verify(secret, totp.codeAt(secret, now.plusSeconds(30)), now)).isPresent();
    }

    @Test
    void rejectsOutsideWindowWrongCodeAndBadFormat() {
        byte[] secret = totp.newSecret();
        Instant now = Instant.parse("2026-11-04T12:00:10Z");
        assertThat(totp.verify(secret, totp.codeAt(secret, now.plusSeconds(120)), now)).isEmpty();
        assertThat(totp.verify(secret, "000000".equals(totp.codeAt(secret, now)) ? "111111" : "000000", now)).isEmpty();
        assertThat(totp.verify(secret, "12345", now)).isEmpty();
        assertThat(totp.verify(secret, "abcdef", now)).isEmpty();
        assertThat(totp.verify(secret, null, now)).isEmpty();
    }

    @Test
    void otpauthUriHasBase32SecretAndIssuer() {
        byte[] secret = totp.newSecret();
        String uri = totp.otpauthUri("App", "a@b.com", secret);
        assertThat(uri).startsWith("otpauth://totp/App:a%40b.com?secret=" + totp.base32(secret)).contains("issuer=App");
    }
}
