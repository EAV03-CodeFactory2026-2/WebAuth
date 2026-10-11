package com.udea.webauth.controllers.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "El correo no puede estar vacío.")
    @Email(message = "El formato del correo es inválido.")
    private String correo;

    @NotBlank(message = "La contraseña no puede estar vacía.")
    private String contrasena;
}
