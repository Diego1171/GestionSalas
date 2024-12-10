package co.edu.ue.controller;


import co.edu.ue.entity.*;
import co.edu.ue.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@RestController
@CrossOrigin("*")
@RequestMapping(value = "api")
public class SalasController {

    @Autowired
    ISalaService service;
    @Autowired
    IEquipoService serviceEquipos;
    @Autowired
    IInventarioService serviceInventario;
    @Autowired
    IUsuarioService serviceUsuario;
    @Autowired
    IReporteService serviceReporte;

    //Salas
    //@CrossOrigin(origins = "http://localhost:4200") //Habilitar Peticion CORS desde el Frontend
    @GetMapping(value = "/ver-salas")
    public List<Sala> listSalas() {
        return service.listSalas();
    }

    @PostMapping(value = "/guardar-sala")
    public List<Sala> insertSala(@RequestBody Sala sala) {
        return service.insertSala(sala);
    }

    @GetMapping(value = "/buscar-sala")
    public Sala findSalaById(@RequestParam int id) {
        return service.findSalaById(id);
    }

    @PutMapping(value = "/actualizar-sala")
    public Sala updateSala(@RequestBody Sala sala) {
        return service.updateSala(sala);
    }

    //Equipos
    @GetMapping(value = "/ver-equipos")
    public List<Equipo> listEquipos() {
        return serviceEquipos.listEquipos();
    }

    @PostMapping(value = "/guardar-equipo")
    public List<Equipo> insertEquipo(@RequestBody Equipo equipo) {
        return serviceEquipos.insertEquipo(equipo);
    }

    @GetMapping(value = "/buscar-equipo")
    public Equipo findEquipoById(@RequestParam int id) {
        return serviceEquipos.findEquipoById(id);
    }

    @PutMapping(value = "/actualizar-equipo")
    public Equipo updateEquipo(@RequestBody Equipo equipo) {
        return serviceEquipos.updateEquipo(equipo);
    }

    //Inventario
    @GetMapping(value="/ver-inventario")
    public List<Inventario> listInventarios(){
        return serviceInventario.listInventarios();
    }

    @PostMapping(value="/guardar-inventario")
    public List<Inventario> insertInventario(@RequestBody Inventario inventario){
        return serviceInventario.insertInventario(inventario);
    }

    @GetMapping(value="/buscar-inventario")
    public Inventario findInventarioById(@RequestParam int id){
        return serviceInventario.findInventarioById(id);
    }

    @PutMapping(value="/actualizar-inventario")
    public Inventario updateInventario(@RequestBody Inventario inventario){
        return serviceInventario.updateInventario(inventario);
    }

    //Usuarios
    @GetMapping(value="/ver-usuarios")
    public List<Usuario> listUsuarios(){
        return serviceUsuario.listUsuarios();
    }
    public ResponseEntity<?> verSalas(Authentication authentication) {
        System.out.println("Usuario autenticado: " + authentication.getName());
        System.out.println("Roles del usuario: " + authentication.getAuthorities());
        return ResponseEntity.ok("Acceso concedido");
    }

    @PostMapping(value="/guardar-usuario")
    public List<Usuario> insertUsuario(@RequestBody Usuario usuario){
        return serviceUsuario.insertUsuario(usuario);
    }

    @GetMapping(value="/buscar-usuario")
    public Usuario findUsuarioById(@RequestParam int id){
        return serviceUsuario.findUsuarioById(id);
    }

    @PutMapping(value="/actualizar-usuario")
    public Usuario updateUsuario(@RequestBody Usuario usuario){
        return serviceUsuario.updateUsuario(usuario);
    }

    //Reportes
    @GetMapping(value="/ver-reportes")
    public List<Reporte> listReportes(){
        return serviceReporte.listReportes();
    }

    @PostMapping(value="/guardar-reporte")
    public List<Reporte> insertReporte(@RequestBody Reporte reporte){
        return serviceReporte.insertReporte(reporte);
    }

    @GetMapping(value="/buscar-reporte")
    public Reporte findReporteById(@RequestParam int id){
        return serviceReporte.findReporteById(id);
    }

    @PutMapping(value="/actualizar-reporte")
    public Reporte updateReporte(@RequestBody Reporte reporte){
        return serviceReporte.updateReporte(reporte);
    }
}