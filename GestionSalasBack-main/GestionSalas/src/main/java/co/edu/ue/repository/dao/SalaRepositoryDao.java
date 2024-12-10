package co.edu.ue.repository.dao;

import co.edu.ue.entity.Sala;
import co.edu.ue.repository.JPA.ISalaJPA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class SalaRepositoryDao implements ISalaRepositoryDao {

    @Autowired
    ISalaJPA jpa;

    @Override
    public List<Sala> insertSala(Sala sala) {
        jpa.save(sala);
        return listSalas();
    }

    @Override
    public Sala updateSala(Sala sala) {
        return jpa.save(sala);
    }

    @Override
    public Sala findSalaById(int id) {
        return jpa.findSalaById(id);
    }

    @Override
    public List<Sala> listSalas() {
        return jpa.findAll();
    }
}
