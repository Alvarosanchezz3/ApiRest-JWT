package alvaro.firstJWT.Config;

import alvaro.firstJWT.User.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean // En este Bean se obtiene el AuthenticationManager de la config de Spring Security
    public AuthenticationManager authenticationManager (AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
    }

    @Bean // Bean de tipo AuthenticationProvider (impl de Spring Security) para autenticar a los usuarios
    public AuthenticationProvider authenticationProvider() {

        // DaoAuthenticationProvider es una interfaz que necesita 2 argumentos para autenticar
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
            authenticationProvider.setUserDetailsService(userDetailService());
            authenticationProvider.setPasswordEncoder(passwordEncoder());
        // Se devuelve la instancia ya configurada
        return authenticationProvider;
    }

    /* Bean de tipo PasswordEncoder (impl de Spring Security) para cifrar y verificar contraseñas usando
     * BCryptPasswordEncoder para generar hashes seguros de contraseñas  */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean // Bean de tipo UserDetailsService que utiliza el UserRepository para buscar un usuario por nombre de usuario
    public UserDetailsService userDetailService() {
        return username -> userRepository.findByUsername(username).
                orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }
}
