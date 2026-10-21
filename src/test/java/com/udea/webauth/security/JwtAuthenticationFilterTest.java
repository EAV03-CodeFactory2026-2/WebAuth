package com.udea.webauth.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private IJwtService jwtService;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterContinuaCadenaSinAutenticarCuandoNoHayHeaderAuthorization() throws Exception {
        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic abc123", "token123", "Bearer", "bearer valid.jwt"})
    void doFilterContinuaCadenaSinAutenticarCuandoHeaderNoTienePrefijoBearer(String header) throws Exception {
        request.addHeader("Authorization", header);

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    void doFilterValidaTokenVacioCuandoHeaderEsSoloBearer() throws Exception {
        request.addHeader("Authorization", "Bearer ");
        when(jwtService.isTokenValid("")).thenReturn(false);

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtService).isTokenValid("");
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterNoAutenticaCuandoTokenEsInvalido() throws Exception {
        request.addHeader("Authorization", "Bearer expired.jwt");
        when(jwtService.isTokenValid("expired.jwt")).thenReturn(false);

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(200, response.getStatus());
        verify(jwtService, never()).extractUserId(any());
        verify(jwtService, never()).extractRoles(any());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterAutenticaConLosRolesDelTokenCuandoTokenEsValido() throws Exception {
        request.addHeader("Authorization", "Bearer valid.jwt");
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("7");
        when(jwtService.extractRoles("valid.jwt")).thenReturn(List.of("Cliente", "Propietario"));

        filter.doFilter(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertInstanceOf(UsernamePasswordAuthenticationToken.class, authentication);
        assertTrue(authentication.isAuthenticated());
        assertEquals("7", authentication.getPrincipal());
        assertNull(authentication.getCredentials());
        assertIterableEquals(List.of("ROLE_CLIENTE", "ROLE_PROPIETARIO"), nombresDeAuthorities(authentication));
        WebAuthenticationDetails details = assertInstanceOf(WebAuthenticationDetails.class, authentication.getDetails());
        assertEquals("127.0.0.1", details.getRemoteAddress());
        assertNull(details.getSessionId());
        verify(jwtService, never()).extractRolActivo(any());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterAutenticaSinAuthoritiesCuandoRolesEstanVacios() throws Exception {
        request.addHeader("Authorization", "Bearer valid.jwt");
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("7");
        when(jwtService.extractRoles("valid.jwt")).thenReturn(List.of());

        filter.doFilter(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
        assertEquals("7", authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().isEmpty());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterNoAutenticaCuandoRolesSonNulos() throws Exception {
        request.addHeader("Authorization", "Bearer valid.jwt");
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("7");
        when(jwtService.extractRoles("valid.jwt")).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterNoAutenticaCuandoTokenNoTieneUserId() throws Exception {
        request.addHeader("Authorization", "Bearer valid.jwt");
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtService, never()).extractRoles(any());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterConservaAutenticacionPreviaDelContexto() throws Exception {
        Authentication previa = new UsernamePasswordAuthenticationToken("previo", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(previa);
        request.addHeader("Authorization", "Bearer valid.jwt");
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("7");

        filter.doFilter(request, response, filterChain);

        assertSame(previa, SecurityContextHolder.getContext().getAuthentication());
        verify(jwtService, never()).extractRoles(any());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void doFilterContinuaCadenaSinAutenticarCuandoExtraccionLanzaExcepcion() throws Exception {
        request.addHeader("Authorization", "Bearer valid.jwt");
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenThrow(new RuntimeException("claims corruptos"));

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(jwtService, never()).extractRoles(any());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    private List<String> nombresDeAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
