package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.entities.UsuarioAuth;
import com.udea.webauth.exceptions.RolNoAsignadoException;
import com.udea.webauth.exceptions.SeleccionRolRequeridaException;
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

    public static final String MSG_ROL_NO_ASIGNADO = "El usuario no tiene asignado el rol solicitado.";
    public static final String MSG_SELECCION_ROL = "La cuenta tiene varios roles. Indica con cuál deseas operar.";
    public static final String MSG_SIN_ROLES = "El usuario no tiene roles asignados.";
    public static final String MSG_TOKEN_INVALIDO = "Token inválido o expirado.";

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

        validarActivo(usuario);

        return emitirToken(usuario, request.getRol(), "Autenticación exitosa");
    }

    @Override
    public AuthResponse cambiarRol(String token, String rol) {
        token = quitarPrefijoBearer(token);
        if (token == null || !jwtService.isTokenValid(token)) {
            throw new IllegalArgumentException(MSG_TOKEN_INVALIDO);
        }

        // Los roles se releen de la BD: si al usuario le quitaron un rol, no puede volver a activarlo.
        Integer usuarioId = Integer.parseInt(jwtService.extractUserId(token));
        UsuarioAuth usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new IllegalArgumentException(MSG_TOKEN_INVALIDO));
        validarActivo(usuario);

        return emitirToken(usuario, rol, "Rol activo actualizado");
    }

    @Override
    public ValidateTokenResponse validateToken(String token) {
        token = quitarPrefijoBearer(token);

        if (token == null || !jwtService.isTokenValid(token)) {
            return ValidateTokenResponse.builder().valid(false).build();
        }

        String userIdStr = jwtService.extractUserId(token);
        String email = jwtService.extractEmail(token);
        List<String> roles = jwtService.extractRoles(token);
        String rolActivo = jwtService.extractRolActivo(token);

        return ValidateTokenResponse.builder()
                .valid(true)
                .userId(userIdStr != null ? Integer.parseInt(userIdStr) : null)
                .email(email)
                .roles(roles)
                .rolActivo(rolActivo)
                .build();
    }

    private AuthResponse emitirToken(UsuarioAuth usuario, String rolSolicitado, String mensaje) {
        List<String> roles = usuario.getRoles().stream()
                .map(r -> r.getNombreRol())
                .sorted()
                .collect(Collectors.toList());

        String rolActivo = resolverRolActivo(roles, rolSolicitado);
        String jwtToken = jwtService.generateToken(usuario.getIdUsuario(), usuario.getCorreo(), roles, rolActivo);

        return AuthResponse.builder()
                .token(jwtToken)
                .mensaje(mensaje)
                .rolActivo(rolActivo)
                .roles(roles)
                .build();
    }

    /**
     * Con rol solicitado: debe estar entre los del usuario (sin distinguir mayúsculas).
     * Sin rol solicitado: si la cuenta tiene un solo rol, ese es el activo; si tiene varios, debe elegir.
     */
    private String resolverRolActivo(List<String> roles, String rolSolicitado) {
        if (roles.isEmpty()) {
            throw new RolNoAsignadoException(MSG_SIN_ROLES);
        }

        if (rolSolicitado != null && !rolSolicitado.isBlank()) {
            return roles.stream()
                    .filter(r -> r.equalsIgnoreCase(rolSolicitado.trim()))
                    .findFirst()
                    .orElseThrow(() -> new RolNoAsignadoException(MSG_ROL_NO_ASIGNADO));
        }

        if (roles.size() == 1) {
            return roles.get(0);
        }
        throw new SeleccionRolRequeridaException(MSG_SELECCION_ROL, roles);
    }

    private void validarActivo(UsuarioAuth usuario) {
        if (!"Activo".equalsIgnoreCase(usuario.getEstado())) {
            throw new IllegalArgumentException("El usuario se encuentra inactivo.");
        }
    }

    private String quitarPrefijoBearer(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.substring(7);
        }
        return token;
    }
}
