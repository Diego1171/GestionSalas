package co.edu.ue.repository.dao;

import java.util.List;
import co.edu.ue.entity.Usuario;

public interface IUsuarioRepositoryDao {
    List<Usuario> insertUsuario(Usuario usuario);
    Usuario updateUsuario(Usuario usuario);
    Usuario findUsuarioById(int id);
    List<Usuario> listUsuarios();
}
