package com.example.app.common;

import jakarta.servlet.http.HttpServletRequest;

public final class ClientInfo {
    private ClientInfo() {}

    /** IP del cliente. Con forward-headers-strategy=native, Tomcat resuelve X-Forwarded-For solo de proxies confiables. */
    public static String ip(HttpServletRequest req) {
        return req.getRemoteAddr();
    }

    public static String userAgent(HttpServletRequest req) {
        return LogSanitizer.clean(req.getHeader("User-Agent"), 255);
    }
}
