package co.edu.ue.service;

import java.util.List;

import co.edu.ue.entity.Equipo;

public interface IEquipoService {
    List<Equipo> insertEquipo(Equipo equipo);
    Equipo updateEquipo(Equipo equipo);
    Equipo findEquipoById(int id);
    List<Equipo> listEquipos();
}
