package com.udea.webauth.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final IJwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = Objects.requireNonNullElse(request.getHeader("Authorization"), "");

        java.util.Optional.of(authHeader)
                .filter(header -> header.regionMatches(true, 0, "Bearer ", 0, 7))
                .map(header -> header.substring(7))
                .ifPresent(jwt -> authenticateValidToken(request, jwt));

        filterChain.doFilter(request, response);
    }

    private void authenticateValidToken(HttpServletRequest request, String jwt) {
        try {
            java.util.Optional.of(jwt)
                    .filter(jwtService::isTokenValid)
                    .map(jwtService::extractUserId)
                    .filter(Objects::nonNull)
                    .filter(userId -> SecurityContextHolder.getContext().getAuthentication() == null)
                    .ifPresent(userId -> authenticate(request, jwt));
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("No se pudo autenticar el token JWT: {}", e.getMessage());
        }
    }

    private void authenticate(HttpServletRequest request, String jwt) {
        List<String> roles = Objects.requireNonNullElse(jwtService.extractRoles(jwt), List.of());
        String rolActivo = jwtService.extractRolActivo(jwt);

        if (StringUtils.hasText(rolActivo)) {
            roles = roles.stream()
                    .filter(rolActivo::equalsIgnoreCase)
                    .toList();
        }

        var authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase(Locale.ROOT)))
                .toList();

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                jwtService.extractUserId(jwt),
                null,
                authorities
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
