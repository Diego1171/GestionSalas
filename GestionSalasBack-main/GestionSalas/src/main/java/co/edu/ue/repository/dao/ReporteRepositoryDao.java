package co.edu.ue.repository.dao;

import co.edu.ue.entity.Reporte;
import co.edu.ue.repository.JPA.IReporteJPA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ReporteRepositoryDao implements IReporteRepositoryDao {

    @Autowired
    IReporteJPA jpa;

    @Override
    public List<Reporte> insertReporte(Reporte reporte) {
        jpa.save(reporte);
        return listReportes();
    }

    @Override
    public Reporte updateReporte(Reporte reporte) {
        return jpa.save(reporte);
    }

    @Override
    public Reporte findReporteById(int id) {
        return jpa.findReporteById(id);
    }

    @Override
    public List<Reporte> listReportes() {
        return jpa.findAll();
    }
}
