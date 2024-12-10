package co.edu.ue.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import co.edu.ue.entity.Equipo;
import co.edu.ue.repository.dao.IEquipoRepositoryDao;

@Service
public class EquipoService implements IEquipoService {

    @Autowired
    IEquipoRepositoryDao dao;

    @Override
    public List<Equipo> insertEquipo(Equipo equipo) {
        return dao.insertEquipo(equipo);
    }

    @Override
    public Equipo updateEquipo(Equipo equipo) {
        return dao.updateEquipo(equipo);
    }

    @Override
    public Equipo findEquipoById(int id) {
        return dao.findEquipoById(id);
    }

    @Override
    public List<Equipo> listEquipos() {
        return dao.listEquipos();
    }
}
