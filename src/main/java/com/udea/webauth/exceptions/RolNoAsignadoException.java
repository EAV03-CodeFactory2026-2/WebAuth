package com.udea.webauth.exceptions;

/**
 * El usuario pidió operar con un rol que no tiene asignado.
 */
public class RolNoAsignadoException extends RuntimeException {
    public RolNoAsignadoException(String message) {
        super(message);
    }
}
