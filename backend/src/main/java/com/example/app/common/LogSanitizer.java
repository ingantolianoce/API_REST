package com.example.app.common;

/** Previene inyeccion en logs: elimina saltos de linea y caracteres de control, y acota la longitud. */
public final class LogSanitizer {
    private LogSanitizer() {}

    public static String clean(String value) {
        return clean(value, 200);
    }

    public static String clean(String value, int max) {
        if (value == null) return null;
        String v = value.length() > max ? value.substring(0, max) : value;
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            sb.append(Character.isISOControl(c) || c == ' ' || c == ' ' ? '_' : c);
        }
        return sb.toString();
    }
}
