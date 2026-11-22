package com.udea.webauth.controllers.DTOs;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "refreshToken")
public class RefreshTokenRequest {

    @NotBlank(message = "El refresh token es obligatorio.")
    private String refreshToken;
}
