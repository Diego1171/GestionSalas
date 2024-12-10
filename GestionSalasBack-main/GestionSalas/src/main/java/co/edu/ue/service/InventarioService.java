package co.edu.ue.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import co.edu.ue.entity.Inventario;
import co.edu.ue.repository.dao.IInventarioRespositoryDao;

@Service
public class InventarioService implements IInventarioService {

    @Autowired
    IInventarioRespositoryDao dao;

    @Override
    public List<Inventario> insertInventario(Inventario inventario) {
        return dao.insertInventario(inventario);
    }

    @Override
    public Inventario updateInventario(Inventario inventario) {
        return dao.updateInventario(inventario);
    }

    @Override
    public Inventario findInventarioById(int id) {
        return dao.findInventarioById(id);
    }

    @Override
    public List<Inventario> listInventarios() {
        return dao.listInventarios();
    }
}
