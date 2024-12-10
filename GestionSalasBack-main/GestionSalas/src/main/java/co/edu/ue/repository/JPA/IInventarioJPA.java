package co.edu.ue.repository.JPA;

import co.edu.ue.entity.Inventario;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IInventarioJPA extends JpaRepository<Inventario, Integer> {
    Inventario findInventarioById(int id);
}
