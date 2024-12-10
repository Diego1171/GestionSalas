package co.edu.ue.repository.dao;
import co.edu.ue.entity.Reporte;
import java.util.List;

public interface IReporteRepositoryDao {
    List<Reporte> insertReporte(Reporte reporte);
    Reporte updateReporte(Reporte reporte);
    Reporte findReporteById(int id);
    List<Reporte> listReportes();
}
