package com.echohealthcare.iam.config;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// Spring Security 7.0 — OAuth2 auth-server configurers live in spring-security-config
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // enables @PreAuthorize on KeyController
public class SecurityConfig {

    /**
     * Filter chain 1 — OAuth2 Authorization Server endpoints.
     *
     * In Spring Security 7.x, {@code applyDefaultSecurity()} was removed.
     * Use {@code http.with(new OAuth2AuthorizationServerConfigurer(), ...)} instead.
     * The configurer's {@code getEndpointsMatcher()} restricts this chain to the
     * well-known OAuth2 / OIDC paths only.
     *
     * PKCE per-client: no global switch needed — the Authorization Server supports
     * PKCE for every client. Whether it is enforced is set per client via
     * ClientSettings.requireProofKey(true/false) in the oauth2_registered_client table.
     */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        // Apply the configurer and customise
        http.with(authorizationServerConfigurer, configurer -> configurer
                // Custom Thymeleaf consent page (see LoginController)
                .authorizationEndpoint(auth -> auth.consentPage("/oauth2/consent"))
                // Enable OIDC: id_token, /userinfo, OIDC logout
                .oidc(withDefaults())
        );

        // Restrict this chain to the authorization server endpoint URLs only
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
            .securityMatcher(endpointsMatcher)
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            // Redirect unauthenticated browser requests to the login page
            .exceptionHandling(ex -> ex
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            // Validate Bearer tokens presented to the /userinfo endpoint
            .oauth2ResourceServer(rs -> rs.jwt(withDefaults()));

        return http.build();
    }

    /**
     * Filter chain 2 — REST API endpoints (/api/**).
     * Requires a valid JWT Bearer token issued by this authorization server.
     * Must be @Order(2) so it is evaluated BEFORE the catch-all default chain.
     */
    @Bean
    @Order(2)
    SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            .oauth2ResourceServer(rs -> rs.jwt(withDefaults()));

        return http.build();
    }

    /**
     * Filter chain 3 — Standard form-login (browser UI).
     * Covers login/consent pages, static resources, Swagger UI, and Actuator health.
     * Must be @Order(3) — catch-all chain (no securityMatcher) must come LAST.
     * Spring Security 7.0 WebSecurityFilterChainValidator enforces this.
     */
    @Bean
    @Order(3)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(
                    "/css/**", "/favicon.ico", "/error",
                    "/login", "/oauth2/consent",
                    "/actuator/health",
                    "/swagger-ui/**", "/swagger-ui.html",
                    "/v3/api-docs/**", "/openapi.yaml"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form.loginPage("/login"));

        return http.build();
    }

    // -------------------------------------------------------------------------
    // Infrastructure beans — all JDBC-backed (no in-memory state)
    // -------------------------------------------------------------------------

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** Stores registered OAuth2 clients in the oauth2_registered_client table. */
    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /** Stores OAuth2 authorizations (codes, tokens) in the oauth2_authorization table. */
    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    /** Stores user consent decisions in the oauth2_authorization_consent table. */
    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }

    /** Loads users from the users + authorities tables (Spring Security schema). */
    @Bean
    UserDetailsManager userDetailsManager(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }
}
