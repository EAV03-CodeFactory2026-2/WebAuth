package com.udea.webauth.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "usuario")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = "roles")
@ToString(exclude = {"roles", "contrasena"})
public class UsuarioAuth {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_usuario")
    private Integer idUsuario;

    @Column(nullable = false, length = 100)
    private String nombre;

    @Column(nullable = false, length = 100)
    private String apellido;

    @Column(nullable = false, unique = true, length = 150)
    private String correo;

    @JsonIgnore
    @Column(nullable = false, length = 255)
    private String contrasena;

    @Column(nullable = false, length = 30)
    @Builder.Default
    private String estado = "Activo";

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "asignacion_rol",
            joinColumns = @JoinColumn(name = "usuario_id"),
            inverseJoinColumns = @JoinColumn(name = "rol_id")
    )
    @Builder.Default
    private Set<RolAuth> roles = new HashSet<>();
}
