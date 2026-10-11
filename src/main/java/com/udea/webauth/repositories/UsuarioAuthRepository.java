package com.udea.webauth.repositories;

import com.udea.webauth.entities.UsuarioAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsuarioAuthRepository extends JpaRepository<UsuarioAuth, Integer> {
    Optional<UsuarioAuth> findByCorreo(String correo);
}
