package co.edu.ue.service;

import java.util.List;

import co.edu.ue.entity.Inventario;

public interface IInventarioService {
    List<Inventario> insertInventario(Inventario inventario);
    Inventario updateInventario(Inventario inventario);
    Inventario findInventarioById(int id);
    List<Inventario> listInventarios();
}
