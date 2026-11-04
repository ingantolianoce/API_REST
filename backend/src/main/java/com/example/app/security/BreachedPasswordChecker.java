package com.example.app.security;

/** Verifica si una contrasena aparece en brechas conocidas. Implementacion por defecto: HIBP con k-anonimato. */
public interface BreachedPasswordChecker {
    /**
     * @param failClosed si el servicio no responde: true => se trata como filtrada (rechaza); false => se permite y se registra.
     */
    boolean isBreached(String password, boolean failClosed);
}
