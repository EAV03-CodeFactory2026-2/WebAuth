package com.udea.webauth.services;

import com.udea.webauth.entities.RefreshToken;
import com.udea.webauth.entities.UsuarioAuth;
import com.udea.webauth.repositories.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;
    private UsuarioAuth usuario;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, 604800000L);
        usuario = UsuarioAuth.builder()
                .idUsuario(1)
                .correo("admin@udea.edu.co")
                .estado("Activo")
                .build();
    }

    @Test
    void crearRefreshTokenGeneraTokenOpacoYGuardaHash() {
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));

        String rawToken = refreshTokenService.crearRefreshToken(usuario, "Propietario");

        assertNotNull(rawToken);
        assertFalse(rawToken.isBlank());

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken saved = captor.getValue();

        assertEquals(64, saved.getTokenHash().length());
        assertNotEquals(rawToken, saved.getTokenHash());
        assertEquals(refreshTokenService.hashToken(rawToken), saved.getTokenHash());
        assertEquals("Propietario", saved.getRolActivo());
        assertEquals(usuario, saved.getUsuario());
        assertFalse(saved.isRevocado());
        assertTrue(saved.getFechaExpiracion().isAfter(Instant.now()));
    }

    @Test
    void validarTokenRetornaEntidadCuandoEsValido() {
        String rawToken = "valid-raw-token";
        RefreshToken stored = RefreshToken.builder()
                .idRefreshToken(10L)
                .tokenHash(refreshTokenService.hashToken(rawToken))
                .usuario(usuario)
                .rolActivo("Propietario")
                .fechaCreacion(Instant.now().minusSeconds(60))
                .fechaExpiracion(Instant.now().plusSeconds(3600))
                .revocado(false)
                .build();

        when(refreshTokenRepository.findByTokenHash(stored.getTokenHash())).thenReturn(Optional.of(stored));

        RefreshToken result = refreshTokenService.validarToken(rawToken);

        assertEquals(stored, result);
        verify(refreshTokenRepository, never()).revocarTodosPorUsuario(any());
    }

    @Test
    void validarTokenLanzaExcepcionCuandoEsVacioONulo() {
        assertThrows(IllegalArgumentException.class, () -> refreshTokenService.validarToken(null));
        assertThrows(IllegalArgumentException.class, () -> refreshTokenService.validarToken("   "));
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void validarTokenLanzaExcepcionCuandoNoExiste() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> refreshTokenService.validarToken("unknown-token")
        );
        assertEquals(RefreshTokenService.MSG_REFRESH_INVALIDO, ex.getMessage());
    }

    @Test
    void validarTokenRevocadoRevocaTodosLosTokensDelUsuario() {
        String rawToken = "reused-token";
        RefreshToken stored = RefreshToken.builder()
                .idRefreshToken(11L)
                .tokenHash(refreshTokenService.hashToken(rawToken))
                .usuario(usuario)
                .rolActivo("Propietario")
                .fechaCreacion(Instant.now().minusSeconds(120))
                .fechaExpiracion(Instant.now().plusSeconds(3600))
                .revocado(true)
                .build();

        when(refreshTokenRepository.findByTokenHash(stored.getTokenHash())).thenReturn(Optional.of(stored));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> refreshTokenService.validarToken(rawToken)
        );
        assertEquals(RefreshTokenService.MSG_REFRESH_INVALIDO, ex.getMessage());
        verify(refreshTokenRepository).revocarTodosPorUsuario(1);
    }

    @Test
    void validarTokenExpiradoMarcaRevocadoYLanzaExcepcion() {
        String rawToken = "expired-token";
        RefreshToken stored = RefreshToken.builder()
                .idRefreshToken(12L)
                .tokenHash(refreshTokenService.hashToken(rawToken))
                .usuario(usuario)
                .rolActivo("Propietario")
                .fechaCreacion(Instant.now().minusSeconds(7200))
                .fechaExpiracion(Instant.now().minusSeconds(10))
                .revocado(false)
                .build();

        when(refreshTokenRepository.findByTokenHash(stored.getTokenHash())).thenReturn(Optional.of(stored));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> refreshTokenService.validarToken(rawToken)
        );
        assertEquals(RefreshTokenService.MSG_REFRESH_INVALIDO, ex.getMessage());
        assertTrue(stored.isRevocado());
        verify(refreshTokenRepository).save(stored);
    }

    @Test
    void revocarTokenMarcaRevocadoYGuarda() {
        RefreshToken stored = RefreshToken.builder().idRefreshToken(13L).revocado(false).build();

        refreshTokenService.revocarToken(stored);

        assertTrue(stored.isRevocado());
        verify(refreshTokenRepository).save(stored);
    }

    @Test
    void revocarPorTokenMarcaRevocadoSiExisteYNoEstaRevocado() {
        String rawToken = "logout-token";
        RefreshToken stored = RefreshToken.builder()
                .idRefreshToken(14L)
                .tokenHash(refreshTokenService.hashToken(rawToken))
                .revocado(false)
                .build();

        when(refreshTokenRepository.findByTokenHash(stored.getTokenHash())).thenReturn(Optional.of(stored));

        refreshTokenService.revocarPorToken(rawToken);

        assertTrue(stored.isRevocado());
        verify(refreshTokenRepository).save(stored);
    }
}
