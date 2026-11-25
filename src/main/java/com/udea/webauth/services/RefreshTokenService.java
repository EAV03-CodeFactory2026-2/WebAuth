package com.udea.webauth.services;

import com.udea.webauth.entities.RefreshToken;
import com.udea.webauth.entities.UsuarioAuth;
import com.udea.webauth.repositories.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class RefreshTokenService implements IRefreshTokenService {

    public static final String MSG_REFRESH_INVALIDO = "Refresh token inválido o expirado.";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_BYTE_LENGTH = 32;

    private final RefreshTokenRepository refreshTokenRepository;
    private final long refreshExpirationMs;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${app.jwt.refresh-expiration-ms:604800000}") long refreshExpirationMs) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    @Override
    @Transactional
    public String crearRefreshToken(UsuarioAuth usuario, String rolActivo) {
        byte[] randomBytes = new byte[TOKEN_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        Instant now = Instant.now();
        RefreshToken entity = RefreshToken.builder()
                .tokenHash(hashToken(rawToken))
                .usuario(usuario)
                .rolActivo(rolActivo)
                .fechaCreacion(now)
                .fechaExpiracion(now.plusMillis(refreshExpirationMs))
                .revocado(false)
                .build();

        refreshTokenRepository.save(entity);
        return rawToken;
    }

    @Override
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public RefreshToken validarToken(String rawToken) {
        RefreshToken token = Optional.ofNullable(rawToken)
                .filter(StringUtils::hasText)
                .map(this::hashToken)
                .flatMap(refreshTokenRepository::findByTokenHash)
                .orElseThrow(() -> new IllegalArgumentException(MSG_REFRESH_INVALIDO));

        Optional.of(token)
                .filter(RefreshToken::isRevocado)
                .ifPresent(reused -> {
                    refreshTokenRepository.revocarTodosPorUsuario(reused.getUsuario().getIdUsuario());
                    throw new IllegalArgumentException(MSG_REFRESH_INVALIDO);
                });

        Optional.of(token)
                .filter(rt -> rt.getFechaExpiracion().isBefore(Instant.now()))
                .ifPresent(expired -> {
                    expired.setRevocado(true);
                    refreshTokenRepository.save(expired);
                    throw new IllegalArgumentException(MSG_REFRESH_INVALIDO);
                });

        return token;
    }

    @Override
    @Transactional
    public void revocarToken(RefreshToken token) {
        token.setRevocado(true);
        refreshTokenRepository.save(token);
    }

    @Override
    @Transactional
    public void revocarPorToken(String rawToken) {
        Optional.ofNullable(rawToken)
                .filter(StringUtils::hasText)
                .map(this::hashToken)
                .flatMap(refreshTokenRepository::findByTokenHash)
                .filter(rt -> !rt.isRevocado())
                .ifPresent(rt -> {
                    rt.setRevocado(true);
                    refreshTokenRepository.save(rt);
                });
    }

    String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algoritmo SHA-256 no disponible.", e);
        }
    }
}
