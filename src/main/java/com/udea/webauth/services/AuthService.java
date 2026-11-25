package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.RefreshTokenRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.entities.RefreshToken;
import com.udea.webauth.entities.RolAuth;
import com.udea.webauth.entities.UsuarioAuth;
import com.udea.webauth.exceptions.RolNoAsignadoException;
import com.udea.webauth.exceptions.SeleccionRolRequeridaException;
import com.udea.webauth.repositories.UsuarioAuthRepository;
import com.udea.webauth.security.IJwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
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
    private final IRefreshTokenService refreshTokenService;

    @Override
    public AuthResponse login(LoginRequest request) {
        UsuarioAuth usuario = usuarioRepository.findByCorreo(request.getCorreo()).orElse(new UsuarioAuth());
        String enviada = Objects.requireNonNullElse(request.getContrasena(), "");
        String guardada = Objects.requireNonNullElse(usuario.getContrasena(), "");

        Optional.of(passwordEncoder.matches(enviada, guardada))
                .filter(Boolean::booleanValue)
                .orElseThrow(() -> new IllegalArgumentException("Credenciales inválidas."));

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

        return emitirToken(
                Optional.ofNullable(usuario)
                        .orElseThrow(() -> new IllegalArgumentException(MSG_TOKEN_INVALIDO)),
                rol,
                "Rol activo actualizado"
        );
    }

    @Override
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        RefreshToken token = refreshTokenService.validarToken(request.getRefreshToken());
        UsuarioAuth usuario = token.getUsuario();
        String rolActivo = token.getRolActivo();

        refreshTokenService.revocarToken(token);
        return emitirToken(usuario, rolActivo, "Token renovado");
    }

    @Override
    public void logout(RefreshTokenRequest request) {
        refreshTokenService.revocarPorToken(request.getRefreshToken());
    }

    @Override
    public ValidateTokenResponse validateToken(String token) {
        String jwt = extraerTokenValido(token)
                .filter(t -> Objects.requireNonNullElse(jwtService.extractUserId(t), "").matches("\\d+"))
                .orElse(null);

        return Optional.ofNullable(jwt)
                .map(validJwt -> ValidateTokenResponse.builder()
                        .valid(true)
                        .userId(Integer.valueOf(jwtService.extractUserId(validJwt)))
                        .email(jwtService.extractEmail(validJwt))
                        .roles(jwtService.extractRoles(validJwt))
                        .rolActivo(jwtService.extractRolActivo(validJwt))
                        .build())
                .orElseGet(() -> ValidateTokenResponse.builder().valid(false).build());
    }

    private AuthResponse emitirToken(UsuarioAuth usuario, String rolSolicitado, String mensaje) {
        Optional.ofNullable(usuario.getEstado())
                .filter(estado -> "Activo".equalsIgnoreCase(estado))
                .orElseThrow(() -> new IllegalArgumentException("El usuario se encuentra inactivo."));

        List<String> roles = usuario.getRoles().stream()
                .map(RolAuth::getNombreRol)
                .sorted()
                .toList();

        String rolActivo = resolverRolActivo(roles, rolSolicitado);
        String jwtToken = jwtService.generateToken(usuario.getIdUsuario(), usuario.getCorreo(), roles, rolActivo);
        String refreshToken = refreshTokenService.crearRefreshToken(usuario, rolActivo);

        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
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
        Optional.of(roles)
                .filter(r -> !r.isEmpty())
                .orElseThrow(() -> new RolNoAsignadoException(MSG_SIN_ROLES));

        if (StringUtils.hasText(rolSolicitado)) {
            return roles.stream()
                    .filter(rolSolicitado.trim()::equalsIgnoreCase)
                    .findFirst()
                    .orElseThrow(() -> new RolNoAsignadoException(MSG_ROL_NO_ASIGNADO));
        }

        return Optional.of(roles)
                .filter(r -> r.size() == 1)
                .map(r -> r.get(0))
                .orElseThrow(() -> new SeleccionRolRequeridaException(MSG_SELECCION_ROL, roles));
    }

    private Optional<String> extraerTokenValido(String token) {
        return Optional.ofNullable(token)
                .filter(t -> t.regionMatches(true, 0, "Bearer ", 0, 7))
                .map(t -> t.substring(7))
                .filter(jwtService::isTokenValid);
    }
}
