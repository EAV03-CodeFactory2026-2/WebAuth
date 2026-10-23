package com.udea.webauth.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * CORS privado: solo se aceptan peticiones de navegador desde los orígenes configurados
 * en CORS_ALLOWED_ORIGINS (separados por coma). No se admite el comodín "*".
 */
@Slf4j
@Configuration
public class CorsConfig {

    private static final List<String> METODOS = List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
    private static final List<String> ENCABEZADOS = List.of("Authorization", "Content-Type");
    private static final long DURACION_PREFLIGHT_SEGUNDOS = 3600;

    @Bean
    public CorsConfigurationSource corsConfigurationSource(@Value("${app.cors.allowed-origins:}") String origenes) {
        List<String> permitidos = Arrays.stream(origenes.split(","))
                .map(String::trim)
                .filter(o -> !o.isEmpty())
                .map(o -> o.endsWith("/") ? o.substring(0, o.length() - 1) : o)
                .toList();

        if (permitidos.contains("*")) {
            throw new IllegalStateException("CORS_ALLOWED_ORIGINS no puede contener '*': https://frontend-self-ten-51.vercel.app");
        }
        if (permitidos.isEmpty()) {
            log.warn("CORS_ALLOWED_ORIGINS está vacío: ningún front podrá llamar a esta API desde el navegador.");
        } else {
            log.info("CORS habilitado para: {}", permitidos);
        }

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(permitidos);
        config.setAllowedMethods(METODOS);
        config.setAllowedHeaders(ENCABEZADOS);
        // El JWT viaja en el encabezado Authorization, no en cookies.
        config.setAllowCredentials(false);
        config.setMaxAge(DURACION_PREFLIGHT_SEGUNDOS);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}