package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;

public interface IAuthService {
    AuthResponse login(LoginRequest request);
    AuthResponse cambiarRol(String token, String rol);
    ValidateTokenResponse validateToken(String token);
}
