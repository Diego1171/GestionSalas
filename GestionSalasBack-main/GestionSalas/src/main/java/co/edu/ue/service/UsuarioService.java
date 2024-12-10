package co.edu.ue.service;

import co.edu.ue.entity.Usuario;
import java.util.List;
import co.edu.ue.repository.dao.IUsuarioRepositoryDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UsuarioService implements IUsuarioService{

    @Autowired
    IUsuarioRepositoryDao dao;

    @Override
    public List<Usuario> insertUsuario(Usuario usuario) {
        return dao.insertUsuario(usuario);
    }

    @Override
    public Usuario updateUsuario(Usuario usuario) {
        return dao.updateUsuario(usuario);
    }

    @Override
    public Usuario findUsuarioById(int id) {
        return dao.findUsuarioById(id);
    }

    @Override
    public List<Usuario> listUsuarios() {
        return dao.listUsuarios();
    }
}
