package co.edu.ue.repository.JPA;

import co.edu.ue.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IUsuarioJPA extends JpaRepository<Usuario, Integer> {
    Usuario findUsuarioById(int id);
}
