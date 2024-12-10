package co.edu.ue.service;


import co.edu.ue.entity.Reporte;
import co.edu.ue.repository.dao.IReporteRepositoryDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class ReporteService implements IReporteService {

    @Autowired
    IReporteRepositoryDao dao;

    @Override
    public List<Reporte> insertReporte(Reporte reporte) {
        return dao.insertReporte(reporte);
    }

    @Override
    public Reporte updateReporte(Reporte reporte) {
        return dao.updateReporte(reporte);
    }

    @Override
    public Reporte findReporteById(int id) {
        return dao.findReporteById  (id);}

    @Override
    public List<Reporte> listReportes() {
        return dao.listReportes();
    }
}
