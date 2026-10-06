package com.sa.common_security.config;

import java.io.IOException;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.sa.common_security.dto.JwtAuthenticatedUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtClaimsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtClaimsFilter.class);

    private final String secretKey;

    public JwtClaimsFilter(
            @Value("${security.jwt.secret-key}") String secretKey) {

        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            String token = header.substring(7);

            Claims claims = Jwts.parser()
                    .verifyWith(key())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            Authentication authentication;

            String type = claims.get("type", String.class);

            if ("SERVICE".equals(type)) {
                authentication = serviceAuth(claims);
            } else {
                authentication = userAuth(claims);
            }

            SecurityContextHolder
                    .getContext()
                    .setAuthentication(authentication);

        } catch (JwtException | IllegalArgumentException e) {

            log.debug(
                    "Token rechazado: {}",
                    e.getClass().getSimpleName());

            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private Authentication userAuth(Claims claims) {

        Number userId = claims.get("userId", Number.class);

        Number profileId = claims.get("profileId", Number.class);

        String username = claims.getSubject();

        List<?> roles = claims.get("roles", List.class);

        if (userId == null || roles == null) {
            throw new IllegalArgumentException(
                    "Claims incompletos");
        }

        List<GrantedAuthority> authorities = roles.stream()
                .map(r -> (GrantedAuthority) new SimpleGrantedAuthority(String.valueOf(r)))
                .toList();

        JwtAuthenticatedUser principal = new JwtAuthenticatedUser(
                userId.longValue(),
                profileId != null
                        ? profileId.longValue()
                        : null,
                username);

        return new UsernamePasswordAuthenticationToken(
                principal,
                null,
                authorities);
    }

    private Authentication serviceAuth(Claims claims) {

        String service = claims.getSubject();

        if (service == null) {
            throw new IllegalArgumentException(
                    "Servicio sin subject");
        }

        return new UsernamePasswordAuthenticationToken(
                service,
                null,
                List.of(
                        new SimpleGrantedAuthority("ROLE_SERVICE")));
    }

    private SecretKey key() {

        return Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(secretKey));
    }
}