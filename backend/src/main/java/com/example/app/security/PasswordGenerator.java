package com.example.app.security;

import java.security.SecureRandom;

/** Contrasenas aleatorias de un solo uso (bootstrap y alta de usuarios). Siempre fuerzan cambio en el primer ingreso. */
public final class PasswordGenerator {
    private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordGenerator() {}

    public static String oneTime() {
        StringBuilder sb = new StringBuilder(24);
        for (int i = 0; i < 24; i++) sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        return sb.toString();
    }
}
