package com.udea.webauth.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String SECRETO = "Y2xhdmUtdW5pdGFyaWEtand0LXNlcnZpY2UtaHMyNTYtMDAwMQ==";
    private static final String SECRETO_AJENO = "b3RyYS1jbGF2ZS1hamVuYS1maXJtYS1qd3QtaHMyNTYtOTk5OQ==";
    private static final String SECRETO_DEBIL = "Y29ydGE=";
    private static final long EXPIRACION_MS = 3_600_000L;

    private static final Integer USUARIO_ID = 7;
    private static final String CORREO = "propietario@udea.edu.co";
    private static final List<String> ROLES = List.of("Cliente", "Propietario");
    private static final String ROL_ACTIVO = "Propietario";

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(SECRETO, EXPIRACION_MS);
    }

    @Test
    void generateTokenRetornaJwtConTresSegmentos() {
        String token = jwtService.generateToken(USUARIO_ID, CORREO, ROLES, ROL_ACTIVO);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void extraccionDeClaimsRetornaLosValoresUsadosAlGenerarElToken() {
        String token = jwtService.generateToken(USUARIO_ID, CORREO, ROLES, ROL_ACTIVO);

        String userId = jwtService.extractUserId(token);
        String email = jwtService.extractEmail(token);
        String rolActivo = jwtService.extractRolActivo(token);
        List<String> roles = jwtService.extractRoles(token);

        assertEquals("7", userId);
        assertEquals(CORREO, email);
        assertEquals(ROL_ACTIVO, rolActivo);
        assertIterableEquals(ROLES, roles);
    }

    @Test
    void extractRolesRetornaListaVaciaCuandoSeGeneraConRolesNulos() {
        String token = jwtService.generateToken(USUARIO_ID, CORREO, null, ROL_ACTIVO);

        List<String> roles = jwtService.extractRoles(token);

        assertNotNull(roles);
        assertTrue(roles.isEmpty());
    }

    @Test
    void extractRolesRetornaListaVaciaCuandoTokenNoTieneClaimRoles() {
        Date ahora = new Date();
        String token = Jwts.builder()
                .subject(String.valueOf(USUARIO_ID))
                .claim("email", CORREO)
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + EXPIRACION_MS))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRETO)))
                .compact();

        List<String> roles = jwtService.extractRoles(token);

        assertNotNull(roles);
        assertTrue(roles.isEmpty());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void extractUserIdLanzaExcepcionCuandoTokenEsNuloOVacio(String token) {
        assertThrows(IllegalArgumentException.class, () -> jwtService.extractUserId(token));
    }

    @Test
    void isTokenValidRetornaTrueCuandoTokenEsRecienGenerado() {
        String token = jwtService.generateToken(USUARIO_ID, CORREO, ROLES, ROL_ACTIVO);

        boolean valido = jwtService.isTokenValid(token);

        assertTrue(valido);
    }

    @Test
    void isTokenValidRetornaFalseCuandoTokenEstaExpirado() {
        JwtService servicioExpirado = new JwtService(SECRETO, -60_000L);
        String token = servicioExpirado.generateToken(USUARIO_ID, CORREO, ROLES, ROL_ACTIVO);

        boolean valido = jwtService.isTokenValid(token);

        assertFalse(valido);
    }

    @Test
    void isTokenValidRetornaFalseCuandoTokenEstaFirmadoConOtraClave() {
        JwtService servicioAjeno = new JwtService(SECRETO_AJENO, EXPIRACION_MS);
        String token = servicioAjeno.generateToken(USUARIO_ID, CORREO, ROLES, ROL_ACTIVO);

        boolean valido = jwtService.isTokenValid(token);

        assertFalse(valido);
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc.def.ghi", "no-es-un-jwt"})
    void isTokenValidRetornaFalseCuandoTokenEstaMalformado(String token) {
        boolean valido = jwtService.isTokenValid(token);

        assertFalse(valido);
    }

    @Test
    void isTokenValidRetornaFalseCuandoPayloadFueAlterado() {
        String[] segmentos = jwtService.generateToken(USUARIO_ID, CORREO, ROLES, ROL_ACTIVO).split("\\.");
        char[] payload = segmentos[1].toCharArray();
        int posicion = payload.length / 2;
        payload[posicion] = payload[posicion] == 'A' ? 'B' : 'A';
        String tokenAlterado = segmentos[0] + "." + new String(payload) + "." + segmentos[2];

        boolean valido = jwtService.isTokenValid(tokenAlterado);

        assertFalse(valido);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isTokenValidRetornaFalseCuandoTokenEsNuloOVacio(String token) {
        boolean valido = jwtService.isTokenValid(token);

        assertFalse(valido);
    }

    @Test
    void constructorLanzaWeakKeyExceptionCuandoSecretoTieneMenosDe256Bits() {
        assertThrows(WeakKeyException.class, () -> new JwtService(SECRETO_DEBIL, EXPIRACION_MS));
    }

    @Test
    void generateTokenLanzaNullPointerExceptionCuandoUsuarioIdEsNulo() {
        NullPointerException ex = assertThrows(
                NullPointerException.class,
                () -> jwtService.generateToken(null, CORREO, ROLES, ROL_ACTIVO)
        );
        assertEquals("El ID del usuario es obligatorio.", ex.getMessage());
    }
}
