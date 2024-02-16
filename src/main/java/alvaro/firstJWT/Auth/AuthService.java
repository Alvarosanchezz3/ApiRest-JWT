package alvaro.firstJWT.Auth;

import alvaro.firstJWT.User.Role;
import alvaro.firstJWT.User.User;
import alvaro.firstJWT.User.UserRepository;
import alvaro.firstJWT.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder; // -> Componente de Spring Security
    private final AuthenticationManager authenticationManager; // -> Componente de Spring Security

    public AuthResponse login(LoginRequest request) {
        // Se autentica el usuario usando el authenticationManager de Spring Security
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        // Se obtiene el usuario de la BDD para conseguir su token
        UserDetails user=userRepository.findByUsername(request.getUsername()).orElseThrow();

        // Se genera un token JWT y se devuelve en un objeto AuthResponse (objeto personalizado)
        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();
    }

    public AuthResponse register(RegisterRequest request) {
        // Se crea un objeto user con la info del request
        User user = User.builder()
            .username(request.getUsername())
            .password(passwordEncoder.encode(request.getPassword())) // Se cifra la contraseña usando passwordEncoder
            .firstname(request.getFirstname())
            .lastname(request.getLastname())
            .country(request.getCountry())
            .role(Role.USER)
            .build();

        // Se guarda el objeto en BDD usando el userRepository
        userRepository.save(user);

        // Se genera un token JWT y se devuelve en un objeto AuthResponse (objeto personalizado)
        return AuthResponse.builder()
            .token(jwtService.getToken(user))
            .build();
    }
}