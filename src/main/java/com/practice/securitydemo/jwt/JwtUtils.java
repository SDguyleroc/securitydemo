package com.practice.securitydemo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
@PropertySource("classpath:application.properties")
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecrete}")
    private String jwtSecrete = "bmRlOHA3cmMxNTJ6MHB1ZW1taWo0Zm56eDlmNWh2bzN0aWxhNm9nMmk0NjRkbzF0bW1qbjViejZ1ZDducnp2NGI0eTZ6ODk5NmFvMGF6YW5wYXI1MGJ1dHZ5bzg5eTJ0Njg4bGwweGU3d2QxOWNvZng5YnNvOGsxZGlqanBlY28";

    @Value("${spring.app.jwtExpirationMS}")
    private int jwtExpirationMS = 900000;

    /**
     * Retrieves the JSON Web Token (JWT) from the Authorization header of the given HttpServletRequest.
     *
     * @param request the HttpServletRequest object containing the Authorization header
     * @return the JWT token if found, or null if the Authorization header is missing or does not start with "Bearer "
     */

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug("BearerToken: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Generates a JSON Web Token (JWT) based on the provided user details.
     *
     * The generated token is signed with a secret key and contains the user's username as its subject.
     * The token's expiration time is set to a configurable amount of time from the current time.
     *
     * @param userDetails the user details to generate the token for
     * @return a compacted JSON Web Token as a URL-safe string
     */

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        List<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return Jwts.builder()
                .subject(username)
                .claim("authorities", authorities)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMS))
                .signWith(key())
                .compact();
    }

    /**
     * Extracts the username from a given JSON Web Token (JWT).
     *
     * The method verifies the token's signature using a secret key and then extracts the subject claim,
     * which is expected to be the username.
     *
     * @param token the JSON Web Token to extract the username from
     * @return the username extracted from the token's subject claim
     */
    public String getUserNameFromJwtToken(String token){
        return Jwts.parser()
                        .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload()
                .getSubject()
                ;
    }

    /**
     * Returns the secret key used for signing and verifying JSON Web Tokens (JWTs).
     *
     * The key is generated from the base64-decoded value of the JWT secret.
     *
     * @return the secret key as an HMAC SHA key
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecrete));
    }

    /**
     * Validates a given JSON Web Token (JWT) by verifying its signature and checking for expiration.
     *
     * If the token is valid, returns true. Otherwise, returns false and logs an error message.
     *
     * @param authToken the JSON Web Token to validate
     * @return true if the token is valid, false otherwise
     */
    public Boolean validateJwtToken( String authToken){
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

}

