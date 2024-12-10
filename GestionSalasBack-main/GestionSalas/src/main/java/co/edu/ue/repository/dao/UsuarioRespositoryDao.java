package co.edu.ue.repository.dao;

import co.edu.ue.entity.Usuario;
import co.edu.ue.repository.JPA.IUsuarioJPA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UsuarioRespositoryDao implements IUsuarioRepositoryDao{

    @Autowired
    IUsuarioJPA jpa;

    @Override
    public List<Usuario> insertUsuario(Usuario usuario) {
        jpa.save(usuario);
        return listUsuarios();
    }

    @Override
    public Usuario updateUsuario(Usuario usuario) {
        return jpa.save(usuario);
    }

    @Override
    public Usuario findUsuarioById(int id) {
        return jpa.findUsuarioById(id);
    }

    @Override
    public List<Usuario> listUsuarios() {
        return jpa.findAll();
    }
}
