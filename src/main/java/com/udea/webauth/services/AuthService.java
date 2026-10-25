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
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

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
        UsuarioAuth usuario = usuarioRepository.findByCorreo(request.getCorreo()).orElse(new UsuarioAuth());
        String guardada = Objects.requireNonNullElse(usuario.getContrasena(), "");

        if (!passwordEncoder.matches(request.getContrasena(), guardada)) {
            throw new IllegalArgumentException("Credenciales inválidas.");
        }

        return emitirToken(usuario, request.getRol(), "Autenticación exitosa");
    }

    @Override
    public AuthResponse cambiarRol(String token, String rol) {
        // Los roles se releen de la BD: si al usuario le quitaron un rol, no puede volver a activarlo.
        UsuarioAuth usuario = extraerTokenValido(token)
                .map(jwtService::extractUserId)
                .filter(id -> id.matches("\\d+"))
                .map(Integer::valueOf)
                .flatMap(usuarioRepository::findById)
                .orElse(null);

        if (usuario == null) {
            throw new IllegalArgumentException(MSG_TOKEN_INVALIDO);
        }

        return emitirToken(usuario, rol, "Rol activo actualizado");
    }

    @Override
    public ValidateTokenResponse validateToken(String token) {
        String jwt = extraerTokenValido(token)
                .filter(t -> Objects.requireNonNullElse(jwtService.extractUserId(t), "").matches("\\d+"))
                .orElse(null);

        if (jwt == null) {
            return ValidateTokenResponse.builder().valid(false).build();
        }

        return ValidateTokenResponse.builder()
                .valid(true)
                .userId(Integer.valueOf(jwtService.extractUserId(jwt)))
                .email(jwtService.extractEmail(jwt))
                .roles(jwtService.extractRoles(jwt))
                .rolActivo(jwtService.extractRolActivo(jwt))
                .build();
    }

    private AuthResponse emitirToken(UsuarioAuth usuario, String rolSolicitado, String mensaje) {
        if (!"Activo".equalsIgnoreCase(usuario.getEstado())) {
            throw new IllegalArgumentException("El usuario se encuentra inactivo.");
        }

        List<String> roles = usuario.getRoles().stream()
                .map(RolAuth::getNombreRol)
                .sorted()
                .toList();

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

        if (StringUtils.hasText(rolSolicitado)) {
            return roles.stream()
                    .filter(rolSolicitado.trim()::equalsIgnoreCase)
                    .findFirst()
                    .orElseThrow(() -> new RolNoAsignadoException(MSG_ROL_NO_ASIGNADO));
        }

        if (roles.size() == 1) {
            return roles.get(0);
        }
        throw new SeleccionRolRequeridaException(MSG_SELECCION_ROL, roles);
    }

    private Optional<String> extraerTokenValido(String token) {
        return Optional.ofNullable(token)
                .filter(t -> t.startsWith("Bearer "))
                .map(t -> t.substring(7))
                .filter(jwtService::isTokenValid);
    }
}
