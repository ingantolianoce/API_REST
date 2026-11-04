package com.example.app.auth;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Implementacion por defecto: solo deja constancia en el log (sin datos personales). Reemplazar por email real. */
@Component
public class LogSecurityNotifier implements SecurityNotifier {
    private static final Logger log = LoggerFactory.getLogger(LogSecurityNotifier.class);

    @Override
    public void notify(UUID userId, String event) {
        log.info("security-notification pendiente de envio user_id={} event={}", userId, event);
    }
}
