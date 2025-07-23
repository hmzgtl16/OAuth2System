package org.example.oauth2.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/products/**")
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().hasAuthority("SCOPE_read")
                )
                .oauth2ResourceServer((oauth2) ->
                        oauth2.jwt(Customizer.withDefaults())
                        /*
                        oauth2.jwt((jwt) ->
                                jwt.jwkSetUri("http://127.0.0.1:9000/oauth2/jwks")
                        )
                        */
                );

        return http.build();
    }

    /*
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("http://127.0.0.1:9000");
    }
    */
}
