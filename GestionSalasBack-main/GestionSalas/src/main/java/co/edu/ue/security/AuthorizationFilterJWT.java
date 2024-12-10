package co.edu.ue.security;

import co.edu.ue.utils.Tools;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class AuthorizationFilterJWT extends BasicAuthenticationFilter {

    public AuthorizationFilterJWT(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String header = request.getHeader(Tools.ENCABEZADO);

        // Verificar si el token está presente y tiene el prefijo correcto
        if (header == null || !header.startsWith(Tools.PREFIJO_TOKEN)) {
            chain.doFilter(request, response);
            return;
        }

        // Obtener los datos del usuario a partir del token
        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);

        if (authentication != null) {
            // Establecer la autenticación en el contexto de seguridad
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(Tools.ENCABEZADO);

        if (token != null) {
            try {
                // Procesar el token para extraer los claims
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(Tools.CLAVE.getBytes())
                        .build()
                        .parseClaimsJws(token.replace(Tools.PREFIJO_TOKEN, ""))
                        .getBody();

                // Obtener información del usuario y roles
                String user = claims.getSubject();
                Date expiration = claims.getExpiration();

                @SuppressWarnings("unchecked")
                List<String> roles = claims.get("authorities") != null ? 
                    (List<String>) claims.get("authorities") : List.of();

                // Validar si el token ha expirado
                if (expiration.before(new Date())) {
                    throw new JwtException("Token expirado");
                }

                // Validar el usuario y construir las autoridades
                if (user != null) {
                    return new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                    );
                }
            } catch (JwtException e) {
                // Manejo de errores de token
                throw new RuntimeException("Token no válido: " + e.getMessage());
            }
        }
        return null;
    }
}
