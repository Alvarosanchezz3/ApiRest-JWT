package alvaro.firstJWT.jwt;

import alvaro.firstJWT.User.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = System.getenv("SECRET_KEY");

    // Método para generar un token sin claims adicionales
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    // Método para generar un token añadiendo claims extras
    private String getToken(Map<String,Object> extraClaims, UserDetails user) {
        return Jwts.builder()
            .setClaims(extraClaims)
            .setSubject(user.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() *1000*60*24))
            .signWith(getKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    // Decodifica la clave secreta en bytes y la convierte en una instancia de Key utilizando HMAC-SHA.
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Consigue el nombre de usuario del token JWT
    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    // Verifica si el token es válido y si coincide el usuario del token con el proporcionado y si el token no ha expirado
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username=getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    // Obtiene todas las claims (información) del token
    private Claims getAllClaims(String token) {
        return Jwts
            .parserBuilder()
            .setSigningKey(getKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    /* Método para obtener una claim (dato) especif del token
     * (Se usa en getExpiration() para obtener solo el claim de la fecha de expiración para verificar luego
     * en isTokenExpired() si el token ha expirado o no)
     *
     * En java 'T' es un tipo genérico que se utiliza para representar cualquier tipo de dato */
    public <T> T getClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims=getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Obtiene la fecha de expiración del token
    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    // Verifica si el token JWT ha expirado comparando su fecha de expiración con la fecha actual
    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }
}