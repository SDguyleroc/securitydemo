package com.practice.securitydemo;

import com.practice.securitydemo.jwt.AuthEntryPointJwt;
import com.practice.securitydemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

   /**
 * Configures the Spring Security filter chain to require authentication for all incoming HTTP requests.
 *
 * @param http the HttpSecurity object to configure
 * @return the configured SecurityFilterChain
 * @throws Exception if an error occurs during configuration
 */


@Bean
SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorizeRequests ->
            authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                    .requestMatchers("/api/signin").permitAll()
                    .anyRequest().authenticated());
    http.sessionManagement(
            session ->
                    session.sessionCreationPolicy(
                            SessionCreationPolicy.STATELESS)
    );
    http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
    //http.httpBasic(withDefaults());
    http.headers(headers -> headers
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin
            )
    );
    http.csrf(AbstractHttpConfigurer::disable);
    http.addFilterBefore(authenticationJwtTokenFilter(),
            UsernamePasswordAuthenticationFilter.class);


    return http.build();
}


    /**
     * Creates a UserDetailsService bean that provides in-memory user authentication.
     *
     * This bean returns an InMemoryUserDetailsManager instance that stores two users:
     * "user1" with the password "nssn99" and the role "USER", and "admin" with the password "nssn99" and the roles "USER" and "ADMIN".
     *
     * The passwords are stored in plaintext using the "{noop}" prefix, which indicates that the password should not be encrypted.
     *
     * @return a UserDetailsService instance that provides in-memory user authentication
     */
    @Bean
    UserDetailsService userDetailsService(DataSource dataSource) {


        return new JdbcUserDetailsManager(dataSource);
        //return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("password1"))
                    .roles("USER")
                    .build();
            UserDetails admin = User.withUsername("admin")
                    //.password(passwordEncoder().encode("adminPass"))
                    .password(passwordEncoder().encode("adminPass"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
