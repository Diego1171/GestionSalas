package co.edu.ue.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "equipos")
public class Equipo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_equipo", nullable = false)
    private Integer id;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "id_sala", nullable = false)
    private co.edu.ue.entity.Sala idSala;

    @Size(max = 100)
    @NotNull
    @Column(name = "nombre", nullable = false, length = 100)
    private String nombre;

    @Size(max = 50)
    @NotNull
    @Column(name = "tipo", nullable = false, length = 50)
    private String tipo;

    @OneToOne(mappedBy = "idEquipo")
    private co.edu.ue.entity.Inventario inventario;

    @OneToMany(mappedBy = "idEquipo")
    private Set<co.edu.ue.entity.Reporte> reportes = new LinkedHashSet<>();

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public co.edu.ue.entity.Sala getIdSala() {
        return idSala;
    }

    public void setIdSala(co.edu.ue.entity.Sala idSala) {
        this.idSala = idSala;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getTipo() {
        return tipo;
    }

    public void setTipo(String tipo) {
        this.tipo = tipo;
    }

    public co.edu.ue.entity.Inventario getInventario() {
        return inventario;
    }

    public void setInventario(co.edu.ue.entity.Inventario inventario) {
        this.inventario = inventario;
    }

    public Set<co.edu.ue.entity.Reporte> getReportes() {
        return reportes;
    }

    public void setReportes(Set<co.edu.ue.entity.Reporte> reportes) {
        this.reportes = reportes;
    }

}