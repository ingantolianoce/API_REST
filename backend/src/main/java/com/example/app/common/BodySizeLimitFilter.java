package com.example.app.common;

import com.example.app.config.AppProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rechaza cuerpos declarados mas grandes que el limite. Para cuerpos "chunked" el limite
 * tambien debe aplicarse en el proxy inverso (client_max_body_size, ver frontend/nginx.conf).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class BodySizeLimitFilter extends OncePerRequestFilter {
    private final long max;

    public BodySizeLimitFilter(AppProperties props) {
        this.max = props.security().maxBodyBytes();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (req.getContentLengthLong() > max) {
            res.setStatus(413);
            res.setContentType("application/json");
            res.getWriter().write("{\"code\":\"PAYLOAD_TOO_LARGE\"}");
            return;
        }
        chain.doFilter(req, res);
    }
}
