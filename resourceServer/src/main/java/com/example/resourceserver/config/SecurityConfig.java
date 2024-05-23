package com.example.resourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

      @Bean
      public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                  .authorizeHttpRequests(req -> {
                        req.requestMatchers("/admin", "/user", "/" ).authenticated();
                  })
                  .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt((jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(
                                    jwt -> new JwtAuthenticationToken(jwt, getDualJwtAuthenticationConverter().convert(jwt))
                              ))
                        )
                  );
            return http.build();
      }
      private DelegatingJwtGrantedAuthoritiesConverter getDualJwtAuthenticationConverter() {

            JwtGrantedAuthoritiesConverter scope = new JwtGrantedAuthoritiesConverter();
            scope.setAuthorityPrefix("SCOPE_");
            scope.setAuthoritiesClaimName("scope");
            JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
            roles.setAuthorityPrefix("ROLE_");
            roles.setAuthoritiesClaimName("roles");
            return new DelegatingJwtGrantedAuthoritiesConverter(scope, roles);
      }
}
