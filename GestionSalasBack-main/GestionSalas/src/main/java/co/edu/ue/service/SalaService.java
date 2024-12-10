package co.edu.ue.service;

import co.edu.ue.entity.Sala;
import co.edu.ue.repository.dao.ISalaRepositoryDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class SalaService implements ISalaService{

    @Autowired
    ISalaRepositoryDao dao;

    @Override
    public List<Sala> insertSala(Sala sala) {
        return dao.insertSala(sala);
    }

    @Override
    public Sala updateSala(Sala sala) {
        return dao.updateSala(sala);
    }

    @Override
    public Sala findSalaById(int id) {
        return dao.findSalaById(id);
    }

    @Override
    public List<Sala> listSalas() {
        return dao.listSalas();
    }
}
