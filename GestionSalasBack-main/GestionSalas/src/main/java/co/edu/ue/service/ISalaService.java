package co.edu.ue.service;

import java.util.List;

import co.edu.ue.entity.Sala;

public interface ISalaService {
    List<Sala> insertSala(Sala sala);
    Sala updateSala(Sala sala);
    Sala findSalaById(int id);
    List<Sala> listSalas();
}
