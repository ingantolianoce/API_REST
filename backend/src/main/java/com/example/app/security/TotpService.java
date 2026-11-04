package com.example.app.security;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

/** TOTP RFC 6238 (SHA-1, 6 digitos, 30 s) con la libreria java-otp. Ventana de +-1 paso. */
@Component
public class TotpService {
    private static final Duration STEP = Duration.ofSeconds(30);
    private final SecureRandom random = new SecureRandom();
    private final TimeBasedOneTimePasswordGenerator generator;

    public TotpService() {
        try {
            this.generator = new TimeBasedOneTimePasswordGenerator(STEP, 6, TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA1);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] newSecret() {
        byte[] s = new byte[20];                    // 160 bits
        random.nextBytes(s);
        return s;
    }

    public String base32(byte[] secret) {
        return new Base32().encodeToString(secret).replace("=", "");
    }

    public String otpauthUri(String issuer, String account, byte[] secret) {
        return "otpauth://totp/" + enc(issuer) + ":" + enc(account) + "?secret=" + base32(secret)
                + "&issuer=" + enc(issuer) + "&algorithm=SHA1&digits=6&period=30";
    }

    /** @return el paso (time-step) validado, para que el llamador impida reutilizar el mismo codigo. */
    public OptionalLong verify(byte[] secret, String code, Instant now) {
        if (code == null || !code.matches("\\d{6}")) return OptionalLong.empty();
        var key = new SecretKeySpec(secret, "HmacSHA1");
        long current = now.getEpochSecond() / STEP.getSeconds();
        OptionalLong match = OptionalLong.empty();
        try {
            for (long step = current - 1; step <= current + 1; step++) {
                String expected = String.format("%06d",
                        generator.generateOneTimePassword(key, Instant.ofEpochSecond(step * STEP.getSeconds())));
                // Sin cortocircuito: se evaluan los 3 pasos y la comparacion es de tiempo constante.
                if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8))) {
                    match = OptionalLong.of(step);
                }
            }
        } catch (InvalidKeyException e) {
            return OptionalLong.empty();
        }
        return match;
    }

    public String codeAt(byte[] secret, Instant at) {
        try {
            return String.format("%06d", generator.generateOneTimePassword(new SecretKeySpec(secret, "HmacSHA1"), at));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
