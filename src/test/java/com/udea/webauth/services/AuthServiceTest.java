package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.entities.RolAuth;
import com.udea.webauth.entities.UsuarioAuth;
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
}
