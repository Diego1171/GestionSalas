package co.edu.ue.repository.dao;

import java.util.List;
import co.edu.ue.entity.Equipo;
public interface IEquipoRepositoryDao {
    List<Equipo> insertEquipo(Equipo equipo);
    Equipo updateEquipo(Equipo equipo);
    Equipo findEquipoById(int id);
    List<Equipo> listEquipos();
}
