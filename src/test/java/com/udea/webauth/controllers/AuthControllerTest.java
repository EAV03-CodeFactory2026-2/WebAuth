package com.udea.webauth.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.udea.webauth.controllers.DTOs.AuthResponse;
import com.udea.webauth.controllers.DTOs.CambiarRolRequest;
import com.udea.webauth.controllers.DTOs.LoginRequest;
import com.udea.webauth.controllers.DTOs.ValidateTokenResponse;
import com.udea.webauth.exceptions.RolNoAsignadoException;
import com.udea.webauth.exceptions.SeleccionRolRequeridaException;
import com.udea.webauth.services.AuthService;
import com.udea.webauth.services.IAuthService;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
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
                .andExpect(jsonPath("$.mensaje").value("Autenticación exitosa"))
                .andExpect(jsonPath("$.contrasena").doesNotExist());
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
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isNotEmpty());
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
                .andExpect(jsonPath("$.email").value("admin@udea.edu.co"))
                .andExpect(jsonPath("$.contrasena").doesNotExist());
    }

    @Test
    void usuarioAuthYLoginRequestNoExponenContrasenaEnJsonNiToString() throws Exception {
        com.udea.webauth.entities.UsuarioAuth usuario = com.udea.webauth.entities.UsuarioAuth.builder()
                .idUsuario(1)
                .nombre("Admin")
                .apellido("UdeA")
                .correo("admin@udea.edu.co")
                .contrasena("SecretoSuperSeguro123!")
                .build();

        LoginRequest loginRequest = LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("SecretoSuperSeguro123!")
                .build();

        String json = objectMapper.writeValueAsString(usuario);
        org.junit.jupiter.api.Assertions.assertFalse(json.contains("contrasena"));
        org.junit.jupiter.api.Assertions.assertFalse(json.contains("SecretoSuperSeguro123!"));
        org.junit.jupiter.api.Assertions.assertFalse(usuario.toString().contains("SecretoSuperSeguro123!"));
        org.junit.jupiter.api.Assertions.assertFalse(loginRequest.toString().contains("SecretoSuperSeguro123!"));
    }

    @Test
    void cambiarRolRetorna200ConTokenNuevoYRolActivo() throws Exception {
        AuthResponse authResponse = AuthResponse.builder()
                .token("nuevo.jwt.token")
                .mensaje("Rol activo actualizado")
                .rolActivo("Proveedor")
                .roles(List.of("Propietario", "Proveedor"))
                .build();
        when(authService.cambiarRol("Bearer valid.token", "Proveedor")).thenReturn(authResponse);

        ResultActions resultado = mockMvc.perform(post("/api/v1/auth/cambiar-rol")
                        .header("Authorization", "Bearer valid.token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cambiarRolJson("Proveedor")));

        resultado.andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("nuevo.jwt.token"))
                .andExpect(jsonPath("$.rolActivo").value("Proveedor"))
                .andExpect(jsonPath("$.mensaje").value("Rol activo actualizado"));
    }

    @Test
    void cambiarRolRetorna401CuandoTokenEsInvalido() throws Exception {
        when(authService.cambiarRol("Bearer expired.token", "Proveedor"))
                .thenThrow(new IllegalArgumentException(AuthService.MSG_TOKEN_INVALIDO));

        ResultActions resultado = mockMvc.perform(post("/api/v1/auth/cambiar-rol")
                        .header("Authorization", "Bearer expired.token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cambiarRolJson("Proveedor")));

        resultado.andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value(AuthService.MSG_TOKEN_INVALIDO));
    }

    @Test
    void cambiarRolRetorna403CuandoRolNoEstaAsignado() throws Exception {
        when(authService.cambiarRol("Bearer valid.token", "Proveedor"))
                .thenThrow(new RolNoAsignadoException(AuthService.MSG_ROL_NO_ASIGNADO));

        ResultActions resultado = mockMvc.perform(post("/api/v1/auth/cambiar-rol")
                        .header("Authorization", "Bearer valid.token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cambiarRolJson("Proveedor")));

        resultado.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value(AuthService.MSG_ROL_NO_ASIGNADO));
    }

    @Test
    void cambiarRolRetorna400CuandoRolEstaEnBlanco() throws Exception {
        String payload = cambiarRolJson("   ");

        ResultActions resultado = mockMvc.perform(post("/api/v1/auth/cambiar-rol")
                        .header("Authorization", "Bearer valid.token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload));

        resultado.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("El rol no puede estar vacío."));
        verifyNoInteractions(authService);
    }

    @Test
    void loginRetorna400ConRolesDisponiblesCuandoCuentaTieneVariosRolesSinSeleccion() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new SeleccionRolRequeridaException(AuthService.MSG_SELECCION_ROL, List.of("Cliente", "Propietario")));

        ResultActions resultado = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(null)));

        resultado.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(AuthService.MSG_SELECCION_ROL))
                .andExpect(jsonPath("$.rolesDisponibles.length()").value(2))
                .andExpect(jsonPath("$.rolesDisponibles[0]").value("Cliente"))
                .andExpect(jsonPath("$.rolesDisponibles[1]").value("Propietario"));
    }

    @Test
    void loginRetorna403CuandoRolSolicitadoNoEstaAsignado() throws Exception {
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new RolNoAsignadoException(AuthService.MSG_ROL_NO_ASIGNADO));

        ResultActions resultado = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson("Proveedor")));

        resultado.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value(AuthService.MSG_ROL_NO_ASIGNADO));
    }

    @Test
    void loginRetorna500ConFormatoUniformeCuandoOcurreExcepcionNoControlada() throws Exception {
        IllegalStateException causa = new IllegalStateException("Fallo inesperado");
        when(authService.login(any(LoginRequest.class))).thenThrow(causa);
        String payload = loginJson(null);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Error interno del servidor."));
    }

    @Test
    void validateRetornaTokenInvalidoSinConsultarServicioCuandoNoHayHeader() throws Exception {
        ResultActions resultado = mockMvc.perform(get("/api/v1/auth/validate"));

        resultado.andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
        verifyNoInteractions(authService);
    }

    @Test
    void validateRetornaTokenInvalidoSinConsultarServicioCuandoHeaderEstaEnBlanco() throws Exception {
        ResultActions resultado = mockMvc.perform(get("/api/v1/auth/validate")
                        .header("Authorization", "   "));

        resultado.andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
        verifyNoInteractions(authService);
    }

    @Test
    void validateRetorna200ConValidFalseCuandoTokenEsInvalido() throws Exception {
        when(authService.validateToken("Bearer invalid.token"))
                .thenReturn(ValidateTokenResponse.builder().valid(false).build());

        ResultActions resultado = mockMvc.perform(get("/api/v1/auth/validate")
                        .header("Authorization", "Bearer invalid.token"));

        resultado.andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
        verify(authService).validateToken("Bearer invalid.token");
    }

    private String cambiarRolJson(String rol) throws Exception {
        return objectMapper.writeValueAsString(CambiarRolRequest.builder().rol(rol).build());
    }

    private String loginJson(String rol) throws Exception {
        return objectMapper.writeValueAsString(LoginRequest.builder()
                .correo("admin@udea.edu.co")
                .contrasena("password123")
                .rol(rol)
                .build());
    }
}
