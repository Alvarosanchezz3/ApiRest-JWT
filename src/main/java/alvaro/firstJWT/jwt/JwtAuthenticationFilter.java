package alvaro.firstJWT.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
@RequiredArgsConstructor
// OncePerRequestFilter sirve para crear filtros personalizados y se ejecuta solo 1 vez por request
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // Este método es el corazón del filtro y se encarga de realizar la lógica de autenticación basada en JWT
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Se obtiene el token usando el método getTokenFromRequest() creado posteriormente
        final String token = getTokenFromRequest(request);
        final String username;

        // Si el token es nulo el filtro pasa la solicitud y la respuesta al siguiente filtro en la cadena
        if (token==null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Si el token no es nulo se obtiene el usuario del token usando el método del jwtService
        username = jwtService.getUsernameFromToken(token);

        // Se verifica si el usuario no es nulo y si no hay autenticación en el contexto de seguridad
        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {

            // Se autenticar al usuario utilizando el UserDetailsService.
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);

            /* Si el usuario se ha auntenticado y el token es válido se crea un objecto
             * 'UsernamePasswordAuthenticationToken' con los detalles del usuario y se establece en el contexto de
             *  seguridad
             */
            if (jwtService.isTokenValid(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        // Se pasa al siguiente filtro en la cadena
        filterChain.doFilter(request, response);
    }

    /* Este método extrae el token JWT del encabezado de autorización de la solicitud
     *
     * Los token JWT a menudo usan el "esquema bearer" --> Authorization: Bearer eyJhbGciOiJI...
     * Verificamos si usa Bearer y si lo usa lo quitamos para quedarnos con el token solo
     */
    public String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}