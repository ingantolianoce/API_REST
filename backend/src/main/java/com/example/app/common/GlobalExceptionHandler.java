package com.example.app.common;

import com.example.app.audit.AuditService;
import com.example.app.audit.AuditService.Result;
import com.example.app.auth.AccountService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Errores consistentes y GENERICOS: codigo estable + ID de correlacion. El detalle va solo al log (fallar cerrado).
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final AuditService audit;

    public GlobalExceptionHandler(AuditService audit) {
        this.audit = audit;
    }

    private static Map<String, Object> body(String code) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("code", code);
        m.put("requestId", MDC.get(RequestIdFilter.MDC_KEY));
        return m;
    }

    @ExceptionHandler(AccountService.PasswordRejectedException.class)
    ResponseEntity<Object> passwordRejected(AccountService.PasswordRejectedException e) {
        Map<String, Object> m = body(e.code());
        m.put("violations", e.violations());
        return ResponseEntity.status(e.status()).body(m);
    }

    @ExceptionHandler(ApiException.class)
    ResponseEntity<Object> api(ApiException e) {
        return ResponseEntity.status(e.status()).body(body(e.code()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<Object> denied(AccessDeniedException e) {
        audit.record("authz.denied", Result.DENIED, "endpoint", "access", "forbidden", Map.of());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body("FORBIDDEN"));
    }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<Object> unauthenticated(AuthenticationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body("UNAUTHENTICATED"));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Object> unexpected(Exception e) {
        log.error("Error no controlado", e);           // detalle solo en el log
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body("INTERNAL_ERROR"));
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers,
                                                                  HttpStatusCode status, WebRequest request) {
        List<String> fields = ex.getBindingResult().getFieldErrors().stream().map(f -> f.getField()).distinct().toList();
        Map<String, Object> m = body("VALIDATION_FAILED");
        m.put("fields", fields);                         // solo nombres de campos; nunca los valores recibidos
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(m);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object payload, HttpHeaders headers,
                                                             HttpStatusCode status, WebRequest request) {
        return ResponseEntity.status(status).headers(headers).body(body("HTTP_" + status.value()));
    }
}
