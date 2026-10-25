package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.entities.RolAuth;
import com.udea.webauth.entities.UsuarioAuth;
import com.udea.webauth.exceptions.RolNoAsignadoException;
import com.udea.webauth.exceptions.SeleccionRolRequeridaException;
import com.udea.webauth.repositories.UsuarioAuthRepository;
import com.udea.webauth.security.IJwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UsuarioAuthRepository usuarioRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private IJwtService jwtService;

    @InjectMocks
    private AuthService authService;

    private UsuarioAuth usuario;

    @BeforeEach
    void setUp() {
        RolAuth rol = RolAuth.builder().idRol(1).nombreRol("Propietario").build();
        usuario = UsuarioAuth.builder()
                .idUsuario(1)
                .nombre("Admin")
                .apellido("Sistema")
                .correo("admin@udea.edu.co")
                .contrasena("$2a$10$hashedpassword")
                .estado("Activo")
                .roles(Set.of(rol))
                .build();
    }

    @Test
    void loginExitoso() {
        LoginRequest request = LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("password123")
                .build();

        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("password123", "$2a$10$hashedpassword")).thenReturn(true);
        when(jwtService.generateToken(eq(1), eq("admin@udea.edu.co"), anyList(), eq("Propietario"))).thenReturn("mocked.jwt.token");

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("mocked.jwt.token", response.getToken());
        assertEquals("Autenticación exitosa", response.getMensaje());
    }

    @Test
    void loginExitosoConHashBcrypt2b() {
        usuario.setContrasena("$2b$10$hashedpassword2b");
        LoginRequest request = loginRequest("password123", null);
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("password123", "$2b$10$hashedpassword2b")).thenReturn(true);
        when(jwtService.generateToken(eq(1), eq("admin@udea.edu.co"), anyList(), eq("Propietario"))).thenReturn("token2b");

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("token2b", response.getToken());
    }

    @Test
    void loginExitosoConHashBcrypt2y() {
        usuario.setContrasena("$2y$10$hashedpassword2y");
        LoginRequest request = loginRequest("password123", null);
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("password123", "$2y$10$hashedpassword2y")).thenReturn(true);
        when(jwtService.generateToken(eq(1), eq("admin@udea.edu.co"), anyList(), eq("Propietario"))).thenReturn("token2y");

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("token2y", response.getToken());
    }

    @Test
    void loginFallaPorContrasenaInvalida() {
        LoginRequest request = LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("wrongpassword")
                .build();

        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("wrongpassword", "$2a$10$hashedpassword")).thenReturn(false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.login(request));
        assertEquals("Credenciales inválidas.", ex.getMessage());
    }

    @Test
    void loginFallaPorUsuarioInactivo() {
        usuario.setEstado("Inactivo");
        LoginRequest request = LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("password123")
                .build();

        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("password123", "$2a$10$hashedpassword")).thenReturn(true);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.login(request));
        assertEquals("El usuario se encuentra inactivo.", ex.getMessage());
    }

    @Test
    void validateTokenExitoso() {
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("1");
        when(jwtService.extractEmail("valid.jwt")).thenReturn("admin@udea.edu.co");
        when(jwtService.extractRoles("valid.jwt")).thenReturn(List.of("Propietario"));

        ValidateTokenResponse response = authService.validateToken("Bearer valid.jwt");

        assertTrue(response.isValid());
        assertEquals(1, response.getUserId());
        assertEquals("admin@udea.edu.co", response.getEmail());
        assertEquals(List.of("Propietario"), response.getRoles());
    }

    @Test
    void loginFallaCuandoUsuarioNoExiste() {
        LoginRequest request = loginRequest("password123", null);
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.empty());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.login(request));

        assertEquals("Credenciales inválidas.", ex.getMessage());
        verify(passwordEncoder, never()).matches(any(), any());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginExitosoConContrasenaEnTextoPlanoQueCoincide() {
        usuario.setContrasena("password123");
        LoginRequest request = loginRequest("password123", null);
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(jwtService.generateToken(1, "admin@udea.edu.co", List.of("Propietario"), "Propietario")).thenReturn("plain.jwt.token");

        AuthResponse response = authService.login(request);

        assertEquals("plain.jwt.token", response.getToken());
        assertEquals("Propietario", response.getRolActivo());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void loginFallaConContrasenaEnTextoPlanoQueNoCoincide() {
        usuario.setContrasena("password123");
        LoginRequest request = loginRequest("wrongpassword", null);
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.login(request));

        assertEquals("Credenciales inválidas.", ex.getMessage());
        verify(passwordEncoder, never()).matches(any(), any());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginFallaCuandoContrasenaGuardadaEsNula() {
        usuario.setContrasena(null);
        LoginRequest request = loginRequest("password123", null);
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.login(request));

        assertEquals("Credenciales inválidas.", ex.getMessage());
        verify(passwordEncoder, never()).matches(any(), any());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginLanzaRolNoAsignadoCuandoUsuarioNoTieneRoles() {
        usuario.setRoles(Set.of());
        LoginRequest request = loginRequest("password123", null);
        stubCredencialesValidas();

        RolNoAsignadoException ex = assertThrows(RolNoAsignadoException.class, () -> authService.login(request));

        assertEquals(AuthService.MSG_SIN_ROLES, ex.getMessage());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginLanzaSeleccionRolRequeridaCuandoUsuarioTieneVariosRolesSinSeleccion() {
        asignarVariosRoles();
        LoginRequest request = loginRequest("password123", null);
        stubCredencialesValidas();

        SeleccionRolRequeridaException ex = assertThrows(SeleccionRolRequeridaException.class, () -> authService.login(request));

        assertEquals(AuthService.MSG_SELECCION_ROL, ex.getMessage());
        assertEquals(List.of("Cliente", "Propietario", "Proveedor"), ex.getRolesDisponibles());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginLanzaSeleccionRolRequeridaCuandoRolSolicitadoEstaEnBlanco() {
        asignarVariosRoles();
        LoginRequest request = loginRequest("password123", "   ");
        stubCredencialesValidas();

        SeleccionRolRequeridaException ex = assertThrows(SeleccionRolRequeridaException.class, () -> authService.login(request));

        assertEquals(AuthService.MSG_SELECCION_ROL, ex.getMessage());
        assertEquals(List.of("Cliente", "Propietario", "Proveedor"), ex.getRolesDisponibles());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginLanzaRolNoAsignadoCuandoRolSolicitadoNoPerteneceAlUsuario() {
        asignarVariosRoles();
        LoginRequest request = loginRequest("password123", "Administrador");
        stubCredencialesValidas();

        RolNoAsignadoException ex = assertThrows(RolNoAsignadoException.class, () -> authService.login(request));

        assertEquals(AuthService.MSG_ROL_NO_ASIGNADO, ex.getMessage());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void loginEmiteTokenConRolActivoSolicitadoSinDistinguirMayusculas() {
        asignarVariosRoles();
        LoginRequest request = loginRequest("password123", "  pRoPiEtArIo  ");
        stubCredencialesValidas();
        List<String> rolesOrdenados = List.of("Cliente", "Propietario", "Proveedor");
        when(jwtService.generateToken(1, "admin@udea.edu.co", rolesOrdenados, "Propietario")).thenReturn("token.jwt");

        AuthResponse response = authService.login(request);

        assertEquals("token.jwt", response.getToken());
        assertEquals("Propietario", response.getRolActivo());
        assertEquals(rolesOrdenados, response.getRoles());
    }

    @Test
    void loginAsignaElUnicoRolCuandoUsuarioTieneSoloUnRolYNoLoIndica() {
        LoginRequest request = loginRequest("password123", null);
        stubCredencialesValidas();
        List<String> roles = List.of("Propietario");
        when(jwtService.generateToken(1, "admin@udea.edu.co", roles, "Propietario")).thenReturn("token.jwt");

        AuthResponse response = authService.login(request);

        assertEquals("Propietario", response.getRolActivo());
        assertEquals(roles, response.getRoles());
    }

    @Test
    void cambiarRolLanzaExcepcionCuandoTokenEsNulo() {
        String token = null;

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.cambiarRol(token, "Propietario"));

        assertEquals(AuthService.MSG_TOKEN_INVALIDO, ex.getMessage());
        verifyNoInteractions(jwtService, usuarioRepository);
    }

    @Test
    void cambiarRolLanzaExcepcionCuandoTokenEsInvalidoOExpirado() {
        when(jwtService.isTokenValid("expired.jwt")).thenReturn(false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.cambiarRol("Bearer expired.jwt", "Propietario"));

        assertEquals(AuthService.MSG_TOKEN_INVALIDO, ex.getMessage());
        verify(jwtService, never()).extractUserId(any());
        verifyNoInteractions(usuarioRepository);
    }

    @Test
    void cambiarRolLanzaExcepcionCuandoUsuarioNoExiste() {
        stubTokenValidoDeUsuario();
        when(usuarioRepository.findById(1)).thenReturn(Optional.empty());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.cambiarRol("Bearer valid.jwt", "Propietario"));

        assertEquals(AuthService.MSG_TOKEN_INVALIDO, ex.getMessage());
    }

    @Test
    void cambiarRolLanzaExcepcionCuandoUsuarioEstaInactivo() {
        usuario.setEstado("Inactivo");
        stubTokenValidoDeUsuario();

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> authService.cambiarRol("Bearer valid.jwt", "Propietario"));

        assertEquals("El usuario se encuentra inactivo.", ex.getMessage());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void cambiarRolLanzaRolNoAsignadoCuandoRolNoPerteneceAlUsuario() {
        stubTokenValidoDeUsuario();

        RolNoAsignadoException ex = assertThrows(RolNoAsignadoException.class, () -> authService.cambiarRol("Bearer valid.jwt", "Proveedor"));

        assertEquals(AuthService.MSG_ROL_NO_ASIGNADO, ex.getMessage());
        verify(jwtService, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    void cambiarRolEmiteTokenNuevoConRolActivoSolicitado() {
        asignarVariosRoles();
        stubTokenValidoDeUsuario();
        List<String> rolesOrdenados = List.of("Cliente", "Propietario", "Proveedor");
        when(jwtService.generateToken(1, "admin@udea.edu.co", rolesOrdenados, "Proveedor")).thenReturn("nuevo.jwt");

        AuthResponse response = authService.cambiarRol("Bearer valid.jwt", "Proveedor");

        assertEquals("nuevo.jwt", response.getToken());
        assertEquals("Rol activo actualizado", response.getMensaje());
        assertEquals("Proveedor", response.getRolActivo());
        assertEquals(rolesOrdenados, response.getRoles());
    }

    @Test
    void cambiarRolAceptaTokenSinPrefijoBearer() {
        stubTokenValidoDeUsuario();
        when(jwtService.generateToken(1, "admin@udea.edu.co", List.of("Propietario"), "Propietario")).thenReturn("nuevo.jwt");

        AuthResponse response = authService.cambiarRol("valid.jwt", "Propietario");

        assertEquals("nuevo.jwt", response.getToken());
        assertEquals("Propietario", response.getRolActivo());
    }

    @Test
    void cambiarRolLanzaExcepcionCuandoSubjectNoEsNumerico() {
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("no-numerico");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> authService.cambiarRol("Bearer valid.jwt", "Propietario"));
        assertEquals(AuthService.MSG_TOKEN_INVALIDO, ex.getMessage());
    }

    @Test
    void validateTokenRetornaInvalidoCuandoTokenEsNulo() {
        String token = null;

        ValidateTokenResponse response = authService.validateToken(token);

        assertFalse(response.isValid());
        assertNull(response.getUserId());
        verifyNoInteractions(jwtService);
    }

    @Test
    void validateTokenRetornaInvalidoSinExtraerClaimsCuandoTokenEsInvalido() {
        when(jwtService.isTokenValid("invalid.jwt")).thenReturn(false);

        ValidateTokenResponse response = authService.validateToken("Bearer invalid.jwt");

        assertFalse(response.isValid());
        assertNull(response.getUserId());
        verify(jwtService, never()).extractUserId(any());
        verify(jwtService, never()).extractEmail(any());
        verify(jwtService, never()).extractRoles(any());
        verify(jwtService, never()).extractRolActivo(any());
    }

    @Test
    void validateTokenRetornaInvalidoCuandoTokenNoTieneSubject() {
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn(null);

        ValidateTokenResponse response = authService.validateToken("Bearer valid.jwt");

        assertFalse(response.isValid());
        assertNull(response.getUserId());
    }

    @Test
    void validateTokenRetornaInvalidoCuandoSubjectNoEsNumerico() {
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("no-numerico");

        ValidateTokenResponse response = authService.validateToken("Bearer valid.jwt");

        assertFalse(response.isValid());
        assertNull(response.getUserId());
    }

    @Test
    void validateTokenAceptaTokenSinPrefijoBearer() {
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("1");
        when(jwtService.extractEmail("valid.jwt")).thenReturn("admin@udea.edu.co");
        when(jwtService.extractRoles("valid.jwt")).thenReturn(List.of("Propietario"));
        when(jwtService.extractRolActivo("valid.jwt")).thenReturn("Propietario");

        ValidateTokenResponse response = authService.validateToken("valid.jwt");

        assertTrue(response.isValid());
        assertEquals(1, response.getUserId());
        assertEquals("admin@udea.edu.co", response.getEmail());
        assertEquals(List.of("Propietario"), response.getRoles());
        assertEquals("Propietario", response.getRolActivo());
    }

    private LoginRequest loginRequest(String contrasena, String rol) {
        return LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena(contrasena)
                .rol(rol)
                .build();
    }

    private void asignarVariosRoles() {
        usuario.setRoles(Set.of(
                RolAuth.builder().idRol(1).nombreRol("Propietario").build(),
                RolAuth.builder().idRol(2).nombreRol("Cliente").build(),
                RolAuth.builder().idRol(3).nombreRol("Proveedor").build()));
    }

    private void stubCredencialesValidas() {
        when(usuarioRepository.findByCorreo("admin@udea.edu.co")).thenReturn(Optional.of(usuario));
        when(passwordEncoder.matches("password123", "$2a$10$hashedpassword")).thenReturn(true);
    }

    private void stubTokenValidoDeUsuario() {
        when(jwtService.isTokenValid("valid.jwt")).thenReturn(true);
        when(jwtService.extractUserId("valid.jwt")).thenReturn("1");
        when(usuarioRepository.findById(1)).thenReturn(Optional.of(usuario));
    }
}
