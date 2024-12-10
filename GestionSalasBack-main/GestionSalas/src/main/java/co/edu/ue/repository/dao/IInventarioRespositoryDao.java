package co.edu.ue.repository.dao;

import java.util.List;
import co.edu.ue.entity.Inventario;
public interface IInventarioRespositoryDao {
    List<Inventario> insertInventario(Inventario inventario);
    Inventario updateInventario(Inventario inventario);
    Inventario findInventarioById(int id);
    List<Inventario> listInventarios();
}
