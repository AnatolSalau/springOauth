package com.example.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


@Configuration
public class SecurityConfig {

      @Bean
      @Order(1)
      public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {

            OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

            http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
            http.exceptionHandling(e -> e
                  .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

            return http.build();
      }

      @Bean
      @Order(2)
      public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
            http
                  .formLogin()
                  .and()
                  .authorizeHttpRequests().anyRequest().authenticated();
            return http.build();
      }

      @Bean
      public UserDetailsService userDetailsService () {
            UserDetails admin = User
                  .withUsername("admin")
                  .password("$2a$12$WpqXTZTHpYh/PqG5pfnWfuvN/yKxoJWSXHC3MWODY4LiOcYodixFm")
                  .roles("ADMIN")
                  .build();
            UserDetails user = User
                  .withUsername("user")
                  .password("$2a$12$aq7XSTeOelMHY9nG1CPeS.CBz/5TnKiazEVzfOBmFF4dOtx5Odryi")
                  .roles("USER")
                  .build();
            InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager(
                  admin, user
            );

            return inMemoryUserDetailsManager;
      }

      @Bean
      public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
      }

      @Bean
      public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
            provider.setPasswordEncoder(passwordEncoder);
            provider.setUserDetailsService(userDetailsService);
            return new ProviderManager(provider);
      }

      @Bean
      public DaoAuthenticationProvider inMemoryDaoAuthenticationProvider() {
            DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
            daoAuthenticationProvider.setUserDetailsService(userDetailsService());
            daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
            return daoAuthenticationProvider;
      }
/*
      @Bean
      public RegisteredClientRepository registeredClientRepository() {
            RegisteredClient registeredClient1 = RegisteredClient.withId(UUID.randomUUID().toString())
                  .clientId("client")
                  .clientSecret("$2a$12$Ah/6RpokivnYEYhFy58pWeAt/3YZB7qtK6fH05tLoWXCTywgtFGOe")
                  .scopes(scopes -> scopes.addAll(Set.of("user.read", "user.write", "roles", OidcScopes.OPENID)))
                  .redirectUri("https://oidcdebugger.com/debug")
                  .redirectUri("https://oauthdebugger.com/debug")
                  .redirectUri("https://springone.io/authorized")
                  .redirectUri("http://127.0.0.1:8081/login/oauth2/code/spring")
                  .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                  .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
                        AuthorizationGrantType.CLIENT_CREDENTIALS,
                        AuthorizationGrantType.AUTHORIZATION_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN)))
                  .build();
            RegisteredClient registeredClient2 = RegisteredClient.withId(UUID.randomUUID().toString())
                  .clientId("client2")
                  .clientSecret("$2a$12$OSv.3I9LIJ2Q1si9UmATwODq.JCykmUVkXpVVRBUXf9DHvILM2SFq")
                  .scopes(scopes -> scopes.addAll(Set.of("user.read", "user.write", "roles", OidcScopes.OPENID)))
                  .redirectUri("https://oidcdebugger.com/debug")
                  .redirectUri("https://oauthdebugger.com/debug")
                  .redirectUri("https://springone.io/authorized")
                  .redirectUri("http://127.0.0.1:8081/login/oauth2/code/spring")
                  .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                  .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
                        AuthorizationGrantType.CLIENT_CREDENTIALS,
                        AuthorizationGrantType.AUTHORIZATION_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN)))
                  .build();

            return new InMemoryRegisteredClientRepository(registeredClient1, registeredClient2);
      }
*/
      @Bean
      public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
            return (context) -> {
                  if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                        context.getClaims().claims((claims) -> {
                              Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
                              roles
                                    .stream()
                                    .map(c -> c.replaceFirst("^ROLE_", ""))
                                    .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                              claims.put("roles", roles);
                        });
                  }
            };
      }

      @Bean
      public AuthorizationServerSettings authorizationServerSettings() {
            return AuthorizationServerSettings.builder().build();
      }

      @Bean
      public TokenSettings tokenSettings() {
            return TokenSettings.builder().build();
      }

      @Bean
      public ClientSettings clientSettings() {
            return ClientSettings.builder()
                  .requireAuthorizationConsent(false)
                  .requireProofKey(false)
                  .build();
      }

      @Bean
      public JWKSource<SecurityContext> jwkSource() {
            RSAKey rsaKey = generateRsa();
            JWKSet jwkSet = new JWKSet(rsaKey);
            return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
      }

      public static RSAKey generateRsa() {
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
      }

      static KeyPair generateRsaKey() {
            KeyPair keyPair;
            try {
                  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                  keyPairGenerator.initialize(2048);
                  keyPair = keyPairGenerator.generateKeyPair();
            } catch (Exception ex) {
                  throw new IllegalStateException(ex);
            }
            return keyPair;
      }
}
