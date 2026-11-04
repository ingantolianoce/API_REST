package com.example.app.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Codigos de recuperacion MFA: 80 bits de entropia, de un solo uso, mostrados una vez y guardados como SHA-256.
 * (Con entropia alta basta un hash rapido; las contrasenas de baja entropia SI usan Argon2id.)
 */
public final class RecoveryCodes {
    private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // sin caracteres ambiguos
    private static final SecureRandom RANDOM = new SecureRandom();

    private RecoveryCodes() {}

    public static List<String> generate(int count) {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (j > 0 && j % 4 == 0) sb.append('-');
                sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
            }
            codes.add(sb.toString());
        }
        return codes;
    }

    public static String normalize(String code) {
        return code == null ? "" : code.replace("-", "").replace(" ", "").toUpperCase();
    }

    public static boolean looksLikeRecoveryCode(String code) {
        return normalize(code).matches("[A-Z2-9]{16}");
    }

    public static String hash(String code) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(normalize(code).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
