package com.udea.webauth.controllers;

import com.udea.webauth.exceptions.RolNoAsignadoException;
import com.udea.webauth.exceptions.SeleccionRolRequeridaException;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuthExceptionHandlerTest {

    private final AuthExceptionHandler handler = new AuthExceptionHandler();

    @Test
    void handleSeleccionRolRequeridaRetorna400ConRoles() {
        SeleccionRolRequeridaException ex = new SeleccionRolRequeridaException("Selecciona un rol", List.of("Cliente", "Proveedor"));

        ResponseEntity<Map<String, Object>> response = handler.handleSeleccionRolRequerida(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Selecciona un rol", response.getBody().get("error"));
        assertEquals(List.of("Cliente", "Proveedor"), response.getBody().get("rolesDisponibles"));
    }

    @Test
    void handleRolNoAsignadoRetorna403() {
        RolNoAsignadoException ex = new RolNoAsignadoException("No tienes ese rol");

        ResponseEntity<Map<String, Object>> response = handler.handleRolNoAsignado(ex);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("No tienes ese rol", response.getBody().get("error"));
    }

    @Test
    void handleIllegalArgumentRetorna401() {
        IllegalArgumentException ex = new IllegalArgumentException("Credenciales inválidas.");

        ResponseEntity<Map<String, Object>> response = handler.handleIllegalArgument(ex);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Credenciales inválidas.", response.getBody().get("error"));
    }

    @Test
    void handleMethodArgumentNotValidRetorna400ConMensajeDelError() throws Exception {
        Method method = getClass().getDeclaredMethod("dummyMethod", String.class);
        MethodParameter parameter = new MethodParameter(method, 0);
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "target");
        bindingResult.addError(new FieldError("target", "field", "El campo es obligatorio"));
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, bindingResult);

        ResponseEntity<Map<String, Object>> response = handler.handleMethodArgumentNotValid(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("El campo es obligatorio", response.getBody().get("error"));
    }

    @Test
    void handleMethodArgumentNotValidUsaMensajePorDefectoSiNoHayErrores() throws Exception {
        Method method = getClass().getDeclaredMethod("dummyMethod", String.class);
        MethodParameter parameter = new MethodParameter(method, 0);
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "target");
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(parameter, bindingResult);

        ResponseEntity<Map<String, Object>> response = handler.handleMethodArgumentNotValid(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Datos de entrada inválidos.", response.getBody().get("error"));
    }

    @Test
    void handleExceptionRetorna500YMensajeGenerico() {
        Exception ex = new RuntimeException("Fallo interno no controlado");

        ResponseEntity<Map<String, Object>> response = handler.handleException(ex);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Ha ocurrido un error inesperado en el servidor.", response.getBody().get("error"));
    }

    private void dummyMethod(String param) {
        // Método auxiliar para construir MethodParameter en tests
    }
}
