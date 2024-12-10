package co.edu.ue.repository.dao;
import java.util.List;
import co.edu.ue.entity.Sala;

public interface ISalaRepositoryDao {
    List<Sala> insertSala(Sala sala);
    Sala updateSala(Sala sala);
    Sala findSalaById(int id);
    List<Sala> listSalas();
}
