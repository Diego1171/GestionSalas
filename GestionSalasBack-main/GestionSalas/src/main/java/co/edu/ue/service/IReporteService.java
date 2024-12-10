package co.edu.ue.service;

import co.edu.ue.entity.Reporte;
import java.util.List;

public interface IReporteService {
    List<Reporte> insertReporte(Reporte reporte);
    Reporte updateReporte(Reporte reporte);
    Reporte findReporteById(int id);
    List<Reporte> listReportes();

}
