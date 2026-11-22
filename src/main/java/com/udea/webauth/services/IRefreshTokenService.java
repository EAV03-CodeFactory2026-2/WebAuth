package com.udea.webauth.services;

import com.udea.webauth.entities.RefreshToken;
import com.udea.webauth.entities.UsuarioAuth;

public interface IRefreshTokenService {

    String crearRefreshToken(UsuarioAuth usuario, String rolActivo);

    RefreshToken validarToken(String rawToken);

    void revocarToken(RefreshToken token);

    void revocarPorToken(String rawToken);
}
