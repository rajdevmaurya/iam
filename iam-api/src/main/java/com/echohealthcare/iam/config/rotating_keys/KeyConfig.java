package com.echohealthcare.iam.config.rotating_keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class KeyConfig {

    /**
     * Text encryptor used to AES-encrypt RSA private/public keys before writing
     * them to the rsa_key_pairs table.
     * Password and salt are read from application.yml (override in production).
     */
    @Bean
    TextEncryptor textEncryptor(
            @Value("${jwt.encryptor.password}") String password,
            @Value("${jwt.encryptor.salt}") String salt) {
        return Encryptors.text(password, salt);
    }

    /** Nimbus JWT encoder backed by the rotating JWK source. */
    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * JWT decoder — required by oauth2ResourceServer().jwt() in filter chains 1 and 3.
     * Delegates to the Authorization Server's standard decoder factory so it uses
     * the same rotating JWK source as the encoder.
     */
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Token generator chain:
     *   JwtGenerator      → access tokens + id_tokens (RS256, includes authorities claim)
     *   AccessTokenGenerator  → opaque access tokens (unused when self-contained format chosen)
     *   RefreshTokenGenerator → refresh tokens
     */
    @Bean
    OAuth2TokenGenerator<OAuth2Token> delegatingOAuth2TokenGenerator(
            JwtEncoder encoder,
            OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
        JwtGenerator generator = new JwtGenerator(encoder);
        generator.setJwtCustomizer(customizer);
        return new DelegatingOAuth2TokenGenerator(
                generator,
                new OAuth2AccessTokenGenerator(),
                new OAuth2RefreshTokenGenerator());
    }
}
