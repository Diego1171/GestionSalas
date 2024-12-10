package co.edu.ue.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

@Entity
@Table(name = "reportes")
public class Reporte {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_reporte", nullable = false)
    private Integer id;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "id_usuario", nullable = false)
    private co.edu.ue.entity.Usuario idUsuario;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "id_equipo", nullable = false)
    private Equipo idEquipo;

    @NotNull
    @Lob
    @Column(name = "descripcion", nullable = false)
    private String descripcion;

    @NotNull
    @Column(name = "fecha_reporte", nullable = false)
    private Instant fechaReporte;

    @NotNull
    @Lob
    @Column(name = "estado", nullable = false)
    private String estado;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public co.edu.ue.entity.Usuario getIdUsuario() {
        return idUsuario;
    }

    public void setIdUsuario(co.edu.ue.entity.Usuario idUsuario) {
        this.idUsuario = idUsuario;
    }

    public Equipo getIdEquipo() {
        return idEquipo;
    }

    public void setIdEquipo(Equipo idEquipo) {
        this.idEquipo = idEquipo;
    }

    public String getDescripcion() {
        return descripcion;
    }

    public void setDescripcion(String descripcion) {
        this.descripcion = descripcion;
    }

    public Instant getFechaReporte() {
        return fechaReporte;
    }

    public void setFechaReporte(Instant fechaReporte) {
        this.fechaReporte = fechaReporte;
    }

    public String getEstado() {
        return estado;
    }

    public void setEstado(String estado) {
        this.estado = estado;
    }

}