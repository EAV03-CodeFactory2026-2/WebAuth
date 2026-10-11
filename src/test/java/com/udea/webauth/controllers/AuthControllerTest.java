package com.udea.webauth.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.services.IAuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private IAuthService authService;

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        AuthController controller = new AuthController(authService);
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.afterPropertiesSet();

        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setValidator(validator)
                .build();
    }

    @Test
    void loginRetorna200CuandoCredencialesSonValidas() throws Exception {
        LoginRequest request = LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("password123")
                .build();

        AuthResponse authResponse = AuthResponse.builder()
                .token("mocked.jwt.token")
                .mensaje("Autenticación exitosa")
                .build();

        when(authService.login(any(LoginRequest.class))).thenReturn(authResponse);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mocked.jwt.token"))
                .andExpect(jsonPath("$.mensaje").value("Autenticación exitosa"));
    }

    @Test
    void loginRetorna401CuandoCredencialesSonInvalidas() throws Exception {
        LoginRequest request = LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("wrongpassword")
                .build();

        when(authService.login(any(LoginRequest.class))).thenThrow(new IllegalArgumentException("Credenciales inválidas."));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Credenciales inválidas."));
    }

    @Test
    void loginRetorna400CuandoPayloadEsInvalido() throws Exception {
        LoginRequest request = LoginRequest.builder()
                .correo("correo-no-valido")
                .contrasena("")
                .build();

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateRetorna200ConDatosDeSesion() throws Exception {
        ValidateTokenResponse response = ValidateTokenResponse.builder()
                .valid(true)
                .userId(1)
                .email("admin@udea.edu.co")
                .roles(List.of("Propietario"))
                .build();

        when(authService.validateToken("Bearer valid.token")).thenReturn(response);

        mockMvc.perform(get("/api/v1/auth/validate")
                        .header("Authorization", "Bearer valid.token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.email").value("admin@udea.edu.co"));
    }
}
