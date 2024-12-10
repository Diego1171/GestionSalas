package co.edu.ue.repository.JPA;

import co.edu.ue.entity.Sala;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ISalaJPA extends JpaRepository<Sala, Integer> {
    Sala findSalaById(int id);
}
