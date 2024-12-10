package co.edu.ue.repository.JPA;

import co.edu.ue.entity.Reporte;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IReporteJPA extends JpaRepository<Reporte, Integer> {
    Reporte findReporteById(int id);
}
