package com.udea.webauth.config;

import com.udea.webauth.security.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class SecurityConfigTest {

    @Test
    void corsConfigurationSourcePermiteOrigenFrontendYNormalizaSlashFinal() {
        SecurityConfig securityConfig = new SecurityConfig(mock(JwtAuthenticationFilter.class));
        ReflectionTestUtils.setField(
                securityConfig,
                "allowedOrigins",
                "https://frontend-self-ten-51.vercel.app/ , , http://localhost:*"
        );

        CorsConfigurationSource source = securityConfig.corsConfigurationSource();
        CorsConfiguration config = source.getCorsConfiguration(new MockHttpServletRequest("OPTIONS", "/api/v1/health"));

        assertNotNull(config);
        assertEquals(
                "https://frontend-self-ten-51.vercel.app",
                config.checkOrigin("https://frontend-self-ten-51.vercel.app")
        );
        assertEquals(
                "http://localhost:5173",
                config.checkOrigin("http://localhost:5173")
        );
        assertTrue(Boolean.TRUE.equals(config.getAllowCredentials()));
    }

    @Test
    void passwordEncoderSoportaTodasLasVersionesDeBCrypt() {
        SecurityConfig securityConfig = new SecurityConfig(mock(JwtAuthenticationFilter.class));

        PasswordEncoder encoder = securityConfig.passwordEncoder();

        assertInstanceOf(BCryptPasswordEncoder.class, encoder);
        String hash2a = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2A).encode("Secreto#123");
        String hash2b = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B).encode("Secreto#123");
        String hash2y = new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2Y).encode("Secreto#123");

        assertTrue(encoder.matches("Secreto#123", hash2a));
        assertTrue(encoder.matches("Secreto#123", hash2b));
        assertTrue(encoder.matches("Secreto#123", hash2y));
    }

    @Test
    void authenticationEntryPointResponde401ConCuerpoJsonError() throws Exception {
        SecurityConfig securityConfig = new SecurityConfig(mock(JwtAuthenticationFilter.class));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/protegido");
        MockHttpServletResponse response = new MockHttpServletResponse();

        securityConfig.authenticationEntryPoint().commence(request, response, new BadCredentialsException("No autenticado"));

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertTrue(response.getContentType().startsWith(MediaType.APPLICATION_JSON_VALUE));
        assertEquals("{\"error\":\"Token inválido o expirado.\"}", response.getContentAsString());
    }
}
