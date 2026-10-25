package com.udea.webauth.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void authenticationEntryPointRetorna401YMensajeEnJson() throws Exception {
        SecurityConfig securityConfig = new SecurityConfig(mock(JwtAuthenticationFilter.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationEntryPoint entryPoint = securityConfig.authenticationEntryPoint();
        assertNotNull(entryPoint);

        entryPoint.commence(request, response, new BadCredentialsException("Sin credenciales"));

        assertEquals(401, response.getStatus());
        assertTrue(response.getContentType().startsWith("application/json"));
        assertEquals("UTF-8", response.getCharacterEncoding());
        assertEquals("{\"error\":\"No autorizado.\"}", response.getContentAsString());
    }

    @Test
    void passwordEncoderRetornaInstanciaValida() {
        SecurityConfig securityConfig = new SecurityConfig(mock(JwtAuthenticationFilter.class));
        PasswordEncoder encoder = securityConfig.passwordEncoder();

        assertNotNull(encoder);
        String encoded = encoder.encode("password123");
        assertTrue(encoder.matches("password123", encoded));
    }
}
