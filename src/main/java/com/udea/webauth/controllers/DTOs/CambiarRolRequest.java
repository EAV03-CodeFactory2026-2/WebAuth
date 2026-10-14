package com.udea.webauth.controllers.DTOs;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CambiarRolRequest {

    @NotBlank(message = "El rol no puede estar vacío.")
    private String rol;
}
