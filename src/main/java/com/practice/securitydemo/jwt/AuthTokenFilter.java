package com.practice.securitydemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * A filter class responsible for authenticating and validating JSON Web Tokens (JWTs) in incoming requests.
 *
 *  This filter extracts the JWT from the request's Authorization header, verifies its signature and expiration,
 *  and extracts the username from the token's subject claim.
 *
 *  If the token is invalid or missing, the filter will reject the request.
 *
 *  If the token is valid, the filter will set the authentication object in the SecurityContextHolder
 *  and create a new UsernamePasswordAuthenticationToken with the user's details.
 * class: AuthTokenFilter
 * author: Guy-leroc Ossebi
 * date: 2023-08-31
 */

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);



    /**
     * Performs the actual filtering of the incoming request.
     *
     * This method is responsible for authenticating the user using the JWT token,
     * and setting the authentication object in the SecurityContextHolder.
     *
     * @param request the incoming HttpServletRequest
     * @param response the outgoing HttpServletResponse
     * @param filterChain the FilterChain to continue processing the request
     * @throws ServletException if an error occurs during filtering
     * @throws IOException if an I/O error occurs during filtering
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }


    /**
     * Parses the JWT from the Authorization header of the incoming request.
     *
     * @param request the incoming HttpServletRequest
     * @return the parsed JWT token, or null if the token is missing or invalid
     */

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}
