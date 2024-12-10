package co.edu.ue.repository.JPA;

import co.edu.ue.entity.Equipo;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IEquipoJPA extends JpaRepository<Equipo, Integer> {
    Equipo findEquipoById(int id);
}
