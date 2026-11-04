package com.example.app.audit;

import com.example.app.common.ClientInfo;
import com.example.app.common.LogSanitizer;
import com.example.app.common.RequestIdFilter;
import com.example.app.security.AppUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.json.JsonMapper;

/**
 * Auditoria de seguridad y de negocio, SOLO-INSERCION (la tabla tiene trigger y el usuario de la app no tiene UPDATE/DELETE).
 * Si no se puede auditar, la operacion falla (fallar cerrado): se escribe dentro de la misma transaccion del cambio.
 * Reglas: `details` NUNCA lleva contrasenas, tokens ni datos personales innecesarios; los textos se sanean.
 */
@Service
public class AuditService {
    public enum Result { OK, DENIED, ERROR }

    private static final Logger auditLog = LoggerFactory.getLogger("audit");
    private final JdbcClient jdbc;
    private final JsonMapper json;

    public AuditService(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /** Registra con el actor tomado del contexto de seguridad actual (si lo hay). */
    public void record(String event, Result result, String resource, String action, String reason, Map<String, Object> details) {
        UUID tenant = null;
        UUID user = null;
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a != null && a.getPrincipal() instanceof AppUserDetails u) {
            tenant = u.tenantId();
            user = u.id();
        }
        recordFor(tenant, user, event, result, resource, action, reason, details);
    }

    /** Registra con actor explicito (p. ej. login, donde aun no hay sesion). */
    public void recordFor(UUID tenantId, UUID userId, String event, Result result, String resource, String action,
                          String reason, Map<String, Object> details) {
        String ip = null;
        String ua = null;
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes sra) {
            HttpServletRequest req = sra.getRequest();
            ip = ClientInfo.ip(req);
            ua = ClientInfo.userAgent(req);
        }
        String requestId = MDC.get(RequestIdFilter.MDC_KEY);
        Map<String, Object> safe = sanitize(details);
        String detailsJson = safe.isEmpty() ? null : json.writeValueAsString(safe);

        jdbc.sql("""
                INSERT INTO audit_log (event, tenant_id, user_id, ip, user_agent, request_id, resource, action, result, reason, details)
                VALUES (:event, :tenant, :user, :ip, :ua, :rid, :resource, :action, :result, :reason, CAST(:details AS jsonb))
                """)
                .param("event", event)
                .param("tenant", tenantId)
                .param("user", userId)
                .param("ip", ip)
                .param("ua", ua)
                .param("rid", requestId)
                .param("resource", LogSanitizer.clean(resource))
                .param("action", LogSanitizer.clean(action))
                .param("result", result.name())
                .param("reason", LogSanitizer.clean(reason))
                .param("details", detailsJson)
                .update();

        // Copia estructurada al log (se envia al almacen separado de logs; ver docs/operations).
        auditLog.info("audit event={} result={} resource={} action={} tenant_id={} user_id={} reason={}",
                event, result, LogSanitizer.clean(resource), LogSanitizer.clean(action), tenantId, userId, LogSanitizer.clean(reason));
    }

    private static Map<String, Object> sanitize(Map<String, Object> details) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (details == null) return out;
        details.forEach((k, v) -> out.put(LogSanitizer.clean(k, 64), v instanceof String s ? LogSanitizer.clean(s, 500) : v));
        return out;
    }
}
