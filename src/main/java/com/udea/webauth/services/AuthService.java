package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.entities.UsuarioAuth;
import com.udea.webauth.repositories.UsuarioAuthRepository;
import com.udea.webauth.security.IJwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService implements IAuthService {

    private final UsuarioAuthRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final IJwtService jwtService;

    @Override
    public AuthResponse login(LoginRequest request) {
        UsuarioAuth usuario = usuarioRepository.findByCorreo(request.getCorreo())
                .orElseThrow(() -> new IllegalArgumentException("Credenciales inválidas."));

        boolean match;
        if (usuario.getContrasena() != null && usuario.getContrasena().startsWith("$2a$")) {
            match = passwordEncoder.matches(request.getContrasena(), usuario.getContrasena());
        } else {
            match = request.getContrasena().equals(usuario.getContrasena());
        }

        if (!match) {
            throw new IllegalArgumentException("Credenciales inválidas.");
        }

        if (!"Activo".equalsIgnoreCase(usuario.getEstado())) {
            throw new IllegalArgumentException("El usuario se encuentra inactivo.");
        }

        List<String> roles = usuario.getRoles().stream()
                .map(r -> r.getNombreRol())
                .collect(Collectors.toList());

        String jwtToken = jwtService.generateToken(usuario.getIdUsuario(), usuario.getCorreo(), roles);

        return AuthResponse.builder()
                .token(jwtToken)
                .mensaje("Autenticación exitosa")
                .build();
    }

    @Override
    public ValidateTokenResponse validateToken(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        if (token == null || !jwtService.isTokenValid(token)) {
            return ValidateTokenResponse.builder().valid(false).build();
        }

        String userIdStr = jwtService.extractUserId(token);
        String email = jwtService.extractEmail(token);
        List<String> roles = jwtService.extractRoles(token);

        return ValidateTokenResponse.builder()
                .valid(true)
                .userId(userIdStr != null ? Integer.parseInt(userIdStr) : null)
                .email(email)
                .roles(roles)
                .build();
    }
}
