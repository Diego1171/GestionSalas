package co.edu.ue.utils;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.http.HttpHeaders;

@OpenAPIDefinition(
        info = @Info(
                title = "Gestion de Salas",
                description = "Salas de Computacion",
                termsOfService = "Aceptar Terminos y Condiciones",
                contact = @Contact(
                        name = "MMR, CJA, SRC",
                        url = "www.uniempresarial.edu.co"
                ),
                version = "1.0"
        ),
        security = @SecurityRequirement(name = "Security TokenJWT")
)
@SecurityScheme(
        name = "Security TokenJWT",
        description = "La seguridad del API es por medio de un Token JWT",
        type = SecuritySchemeType.HTTP,
        paramName = HttpHeaders.AUTHORIZATION,
        in = SecuritySchemeIn.HEADER,
        scheme = "bearer", bearerFormat = "JWT"
)
public class SwaggerConfig {
}
