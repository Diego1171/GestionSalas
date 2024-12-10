package co.edu.ue.repository.dao;


import co.edu.ue.entity.Inventario;
import co.edu.ue.repository.JPA.IInventarioJPA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public class InventarioRespositoryDao implements IInventarioRespositoryDao {

    @Autowired
    IInventarioJPA jpa;

    @Override
    public List<Inventario> insertInventario(Inventario inventario) {
        jpa.save(inventario);
        return listInventarios();
    }

    @Override
    public Inventario updateInventario(Inventario inventario) {
        return jpa.save(inventario);
    }

    @Override
    public Inventario findInventarioById(int id) {
        return jpa.findInventarioById(id);
    }

    @Override
    public List<Inventario> listInventarios() {
        return jpa.findAll();
    }
}
