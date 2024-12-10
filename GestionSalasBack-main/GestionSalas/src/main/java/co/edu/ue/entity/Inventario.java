package co.edu.ue.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

@Entity
@Table(name = "inventario")
public class Inventario {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_inventario", nullable = false)
    private Integer id;

    @NotNull
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "id_equipo", nullable = false)
    private Equipo idEquipo;

    @NotNull
    @Column(name = "cantidad_disponible", nullable = false)
    private Integer cantidadDisponible;

    @NotNull
    @Column(name = "fecha_actualizacion", nullable = false)
    private Instant fechaActualizacion;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Equipo getIdEquipo() {
        return idEquipo;
    }

    public void setIdEquipo(Equipo idEquipo) {
        this.idEquipo = idEquipo;
    }

    public Integer getCantidadDisponible() {
        return cantidadDisponible;
    }

    public void setCantidadDisponible(Integer cantidadDisponible) {
        this.cantidadDisponible = cantidadDisponible;
    }

    public Instant getFechaActualizacion() {
        return fechaActualizacion;
    }

    public void setFechaActualizacion(Instant fechaActualizacion) {
        this.fechaActualizacion = fechaActualizacion;
    }

}