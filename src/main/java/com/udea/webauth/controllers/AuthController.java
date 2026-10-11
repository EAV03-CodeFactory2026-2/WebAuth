package com.udea.webauth.controllers;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.services.IAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
            description = "Autentica un usuario mediante correo y contraseña. Si las credenciales son válidas, retorna un token JWT que incluye claims de identidad y roles."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Autenticación exitosa. Se retorna el token JWT."),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas o usuario inactivo.")
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            AuthResponse response = authService.login(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
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
        if (authHeader == null || authHeader.isBlank()) {
            return ResponseEntity.ok(ValidateTokenResponse.builder().valid(false).build());
        }
        ValidateTokenResponse response = authService.validateToken(authHeader);
        return ResponseEntity.ok(response);
    }
}
