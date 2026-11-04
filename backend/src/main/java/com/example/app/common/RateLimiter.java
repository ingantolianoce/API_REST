package com.example.app.common;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Limitador de ventana deslizante EN MEMORIA. Valido para una sola instancia;
 * con varias instancias reemplazar por una implementacion compartida (Redis/BD) tras la misma interfaz.
 * Falla cerrado: si se llena la tabla de claves, se deniega.
 */
@Component
public class RateLimiter {
    private static final int MAX_KEYS = 100_000;
    private final ConcurrentHashMap<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    /** @return segundos de espera si se excede el limite; 0 si se permite. */
    public long tryAcquire(String key, int limit, Duration window) {
        if (limit <= 0) return Math.max(1, window.toSeconds());      // limite 0 = siempre denegar
        long now = System.currentTimeMillis();
        long windowMs = window.toMillis();
        if (hits.size() > MAX_KEYS) {
            purge(now, windowMs);
            if (hits.size() > MAX_KEYS) return Math.max(1, window.toSeconds());
        }
        Deque<Long> q = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() >= windowMs) q.pollFirst();
            if (q.size() >= limit) {
                long wait = (windowMs - (now - q.peekFirst()) + 999) / 1000;
                return Math.max(1, wait);
            }
            q.addLast(now);
            return 0;
        }
    }

    public void reset() {
        hits.clear();
    }

    private void purge(long now, long windowMs) {
        hits.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                Long last = e.getValue().peekLast();
                return last == null || now - last >= windowMs;
            }
        });
    }
}
