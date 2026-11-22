package com.udea.webauth.services;

import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.RefreshTokenRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;

public interface IAuthService {
    AuthResponse login(LoginRequest request);
    AuthResponse cambiarRol(String token, String rol);
    AuthResponse refreshToken(RefreshTokenRequest request);
    void logout(RefreshTokenRequest request);
    ValidateTokenResponse validateToken(String token);
}
