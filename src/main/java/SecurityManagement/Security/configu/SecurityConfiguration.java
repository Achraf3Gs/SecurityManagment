package SecurityManagement.Security.configu;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static SecurityManagement.Security.users.Permission.*;
import static SecurityManagement.Security.users.Role.ADMIN;
import static SecurityManagement.Security.users.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity()
public class SecurityConfiguration {


    private static final String[] WHITE_LISTE_URL = {"/", "/index.html", "/home", "/styles**", "/runtime**", "/polyfills**",
            "/main**", "/favicon.ico", "/assets/**", "/*.js", "/*.css"};
    private  final JwtAuthenticationFilter jwtAuthFilter;

    private final AuthenticationProvider authenticationProvider;

    private final LogoutHandler logoutHandler;



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(WHITE_LISTE_URL).permitAll()
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/authenticate").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/Register").permitAll()
                        .requestMatchers("api/v1/management/**").hasAnyRole(ADMIN.name(),MANAGER.name())

                        .requestMatchers(GET,"api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(),MANAGER_READ.name())
                        .requestMatchers(POST,"api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(),MANAGER_READ.name())
                        .requestMatchers(PUT,"api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(),MANAGER_READ.name())
                        .requestMatchers(DELETE,"api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(),MANAGER_READ.name())

                       /* .requestMatchers("api/v1/admin/**").hasAnyRole(ADMIN.name())

                        .requestMatchers(GET,"api/v1/admin/**").hasAnyAuthority(ADMIN_READ.name())
                        .requestMatchers(POST,"api/v1/admin/**").hasAnyAuthority(ADMIN_UPDATE.name())
                        .requestMatchers(PUT,"api/v1/admin/**").hasAnyAuthority(ADMIN_CREATE.name())
                        .requestMatchers(DELETE,"api/v1/admin/**").hasAnyAuthority(ADMIN_DELETE.name())*/
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler((request, response, authentication) ->
                                SecurityContextHolder.clearContext())
                );
        return http.build();
    }




}
