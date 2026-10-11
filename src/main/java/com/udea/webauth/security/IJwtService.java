package com.udea.webauth.security;

import java.util.List;

public interface IJwtService {
    String generateToken(Integer usuarioId, String email, List<String> roles);
    String extractUserId(String token);
    String extractEmail(String token);
    List<String> extractRoles(String token);
    boolean isTokenValid(String token);
}
