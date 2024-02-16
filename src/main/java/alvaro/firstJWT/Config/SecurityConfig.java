package alvaro.firstJWT.Config;

import alvaro.firstJWT.jwt.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authProvider;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationProvider authProvider) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authProvider = authProvider;
    }

    /* Método que configura la cadena de filtros de seguridad. Utiliza un flujo de configuración estilo
     * DSL (Domain Specific Language) para definir las reglas de seguridad. */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable() // Deshabilita la protección CSRF (Cross-Site Request Forgery) para el uso de JWT

                /* Permite el acceso a todas las URL que comiencen con "/auth" sin autenticación y requiere
                 * autenticación para cualquier otra URL. */
                .authorizeRequests(authorizeRequests -> authorizeRequests.requestMatchers("/auth/**")
                        .permitAll().anyRequest().authenticated()
                )

                // Configura la gestión de sesiones, en este caso la aplicación no creará ni utilizará sesiones HTTP
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Configura el proveedor de autenticación que se utilizará para autenticar a los usuarios.
                .authenticationProvider(authProvider)

                // Añade el filtro que hemos creado para ejecutarse antes del filtro predeterminado
                .addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class)

                // Configura el manejo de excepciones relacionadas con la autenticación.
                .exceptionHandling()
                .and()
                .build();
    }
}
