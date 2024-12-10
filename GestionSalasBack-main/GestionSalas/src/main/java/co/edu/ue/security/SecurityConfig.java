package co.edu.ue.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    AuthenticationManager auth;

    @Bean
    public AuthenticationManager authManager(AuthenticationConfiguration conf) {
        try {
            auth = conf.getAuthenticationManager();
        } catch (Exception e) {
            System.out.println("" + e.getMessage());
            e.printStackTrace();
        }
        return auth;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(cus -> cus.disable()) // Deshabilitar CSRF para pruebas
                .authorizeHttpRequests(aut -> aut
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/ver-sala").hasRole("ADMINS")
                        .requestMatchers(HttpMethod.GET, "/api/ver-equipo").hasRole("ADMINS")
                        .requestMatchers(HttpMethod.GET, "/api/ver-reporte").hasRole("ADMINS")
                        .requestMatchers(HttpMethod.GET, "/api/ver-inventarios").hasRole("ADMINS")
                        .requestMatchers(HttpMethod.GET, "/*").authenticated()
                        .anyRequest().permitAll()
                ).addFilter(new AuthorizationFilterJWT(auth));
        return http.build();
    }

    @Bean
    public JdbcUserDetailsManager jdbcUserDetails() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("com.mysql.cj.jdbc.Driver");
        ds.setUrl("jdbc:mysql://localhost:3306/gestionsalas");
        ds.setUsername("root");
        ds.setPassword("");

        JdbcUserDetailsManager jdbcUserDetails = new JdbcUserDetailsManager(ds);

        // Consulta para obtener usuarios (nombre de usuario, contraseña, y habilitación)
        jdbcUserDetails.setUsersByUsernameQuery(
                "SELECT correo AS username, contraseña AS password, estado as estado FROM usuarios WHERE estado = 1 AND correo = ?");
        jdbcUserDetails.setAuthoritiesByUsernameQuery(
                "SELECT correo AS username, tipo AS rol FROM usuarios WHERE correo = ?");

        printUsers(ds);
        return jdbcUserDetails;
    }

    private void printUsers(DriverManagerDataSource ds) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);

        List<String> users = jdbcTemplate.queryForList("SELECT correo FROM usuarios", String.class);
        System.out.println("Usuarios: " + users);
        List<String> roles = jdbcTemplate.queryForList("SELECT tipo FROM usuarios", String.class);
        System.out.println("Roles: " + roles);
        List<String> passwords = jdbcTemplate.queryForList("SELECT contraseña FROM usuarios", String.class);
        System.out.println("Contraseñas: " + passwords);
    }
}