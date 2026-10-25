package com.udea.webauth.controllers;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.CambiarRolRequest;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.exceptions.RolNoAsignadoException;
import com.udea.webauth.exceptions.SeleccionRolRequeridaException;
import com.udea.webauth.services.IAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticación", description = "Endpoints para el inicio de sesión y validación de tokens JWT")
public class AuthController {

    private final IAuthService authService;

    @Operation(
            summary = "Iniciar sesión",
            description = "Autentica un usuario mediante correo y contraseña. Si las credenciales son válidas, retorna un token JWT "
                    + "con claims de identidad, roles y rol activo. El campo opcional `rol` elige el rol activo; "
                    + "es obligatorio si la cuenta tiene varios roles."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Autenticación exitosa. Se retorna el token JWT."),
            @ApiResponse(responseCode = "400", description = "La cuenta tiene varios roles y no indicó cuál usar (incluye rolesDisponibles)."),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas o usuario inactivo."),
            @ApiResponse(responseCode = "403", description = "El usuario no tiene asignado el rol solicitado.")
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @Operation(
            summary = "Cambiar rol activo",
            description = "Con un token válido, emite un token nuevo cuyo rol activo es el indicado. "
                    + "El rol debe estar asignado al usuario."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Rol activo cambiado. Se retorna un token nuevo."),
            @ApiResponse(responseCode = "401", description = "Token ausente, inválido o expirado, o usuario inactivo."),
            @ApiResponse(responseCode = "403", description = "El usuario no tiene asignado el rol solicitado.")
    })
    @PostMapping("/cambiar-rol")
    public ResponseEntity<AuthResponse> cambiarRol(@RequestHeader(value = "Authorization", required = false) String authHeader,
                                        @Valid @RequestBody CambiarRolRequest request) {
        return ResponseEntity.ok(authService.cambiarRol(authHeader, request.getRol()));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> error(RuntimeException e) {
        return switch (e) {
            case SeleccionRolRequeridaException s -> ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", s.getMessage(), "rolesDisponibles", s.getRolesDisponibles()));
            case RolNoAsignadoException r -> ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", r.getMessage()));
            case IllegalArgumentException i -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", i.getMessage()));
            default -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error interno del servidor."));
        };
    }

    @Operation(
            summary = "Validar token JWT",
            description = "Verifica si el token Bearer JWT provisto es válido y retorna los datos decodificados de la sesión."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token válido o inválido retornado con su respectivo estado.")
    })
    @GetMapping("/validate")
    public ResponseEntity<ValidateTokenResponse> validateToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (!StringUtils.hasText(authHeader)) {
            return ResponseEntity.ok(ValidateTokenResponse.builder().valid(false).build());
        }
        ValidateTokenResponse response = authService.validateToken(authHeader);
        return ResponseEntity.ok(response);
    }
}
