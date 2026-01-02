package com.alexivashchenko.gateway.service.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtGatewayFilter implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(JwtGatewayFilter.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.header:Authorization}")
    private String authHeader;

    @Value("${jwt.prefix:Bearer }")
    private String prefix;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Allow unauthenticated access to auth endpoints
        if (path.startsWith("/api/v1/auth/") || path.equals("/api/v1/auth")) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        String header = request.getHeaders().getFirst(authHeader);

        if (header == null || !header.startsWith(prefix)) {
            return unauthorized(exchange, "Missing or invalid Authorization header");
        }

        String token = header.substring(prefix.length()).trim();

        try {
            // parse and validate token
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();

            String userId = claims.getSubject(); //claims.get("sub", String.class);
//            String userId = claims.get("userId", String.class);
            String email = claims.get("email", String.class);

            if (userId == null || userId.isEmpty()) {
                return unauthorized(exchange, "Token does not contain userId claim");
            }

//            ServerHttpRequest mutated = request.mutate()
//                    .header("X-User-Id", userId)
////                    .header("X-User-Email", email == null ? "" : email)
//                    .build();

            ServerHttpRequest mutated = exchange.getRequest()
                    .mutate()
                    .headers(headers -> {
                        headers.remove("X-User-Id"); // prevent spoofing
                        headers.add("X-User-Id", userId);
                    })
                    .build();

            ServerWebExchange mutatedExchange = exchange.mutate().request(mutated).build();
            return chain.filter(mutatedExchange);

        } catch (Exception ex) {
            log.warn("JWT validation failed: {}", ex.getMessage());
            return unauthorized(exchange, "Invalid or expired token");
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", System.currentTimeMillis());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());
        body.put("message", message);
        body.put("path", exchange.getRequest().getURI().getPath());

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (Exception e) {
            bytes = ("{\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        }

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory()
                .wrap(bytes)));
    }

    // Ensure this runs early
    @Override
    public int getOrder() {
        return -100;
    }
}
