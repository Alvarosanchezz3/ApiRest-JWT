package alvaro.firstJWT.Demo;

import alvaro.firstJWT.jwt.JwtAuthenticationFilter;
import alvaro.firstJWT.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class DemoController {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtService jwtService;

    @PostMapping("demo")
    public ResponseEntity<?> welcome(HttpServletRequest request) {
            String token = jwtAuthenticationFilter.getTokenFromRequest(request);
            String username = jwtService.getUsernameFromToken(token);

            // Extraer solo el nombre de usuario del correo electrónico
            String[] parts = username.split("@");
            String usernameWithoutDomain = parts[0];
            return ResponseEntity.ok("Welcome " + usernameWithoutDomain + " from secure endpoint");
    }
}