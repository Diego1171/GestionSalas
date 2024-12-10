package co.edu.ue.repository.dao;

import co.edu.ue.entity.Equipo;
import co.edu.ue.repository.JPA.IEquipoJPA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class EquipoRespositoryDao implements IEquipoRepositoryDao {

    @Autowired
    IEquipoJPA jpa;

    @Override
    public List<Equipo> insertEquipo(Equipo equipo) {
        return null;
    }

    @Override
    public Equipo updateEquipo(Equipo equipo) {
        return null;
    }

    @Override
    public Equipo findEquipoById(int id) {
        return null;
    }

    @Override
    public List<Equipo> listEquipos() {
        return null;
    }
}
