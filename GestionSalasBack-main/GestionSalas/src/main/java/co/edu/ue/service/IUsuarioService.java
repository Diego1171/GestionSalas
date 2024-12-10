package co.edu.ue.service;

import co.edu.ue.entity.Usuario;
import java.util.List;

public interface IUsuarioService {
    List<Usuario> insertUsuario(Usuario usuario);
    Usuario updateUsuario(Usuario usuario);
    Usuario findUsuarioById(int id);
    List<Usuario> listUsuarios();
}
