package com.udea.webauth.controllers.DTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ValidateTokenResponse {
    private boolean valid;
    private Integer userId;
    private String email;
    private List<String> roles;
    private String rolActivo;
}
