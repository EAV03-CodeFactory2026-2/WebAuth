package com.udea.webauth.exceptions;

import lombok.Getter;

import java.util.List;

/**
 * La cuenta tiene varios roles y no indicó con cuál quiere operar.
 */
@Getter
public class SeleccionRolRequeridaException extends RuntimeException {

    private final List<String> rolesDisponibles;

    public SeleccionRolRequeridaException(String message, List<String> rolesDisponibles) {
        super(message);
        this.rolesDisponibles = rolesDisponibles;
    }
}
