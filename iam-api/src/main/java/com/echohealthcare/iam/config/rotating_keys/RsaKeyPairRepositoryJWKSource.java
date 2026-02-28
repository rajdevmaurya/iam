package com.echohealthcare.iam.config.rotating_keys;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Serves two roles:
 * <ol>
 *   <li>{@link JWKSource} — exposes the RSA public keys at /oauth2/jwks for token verification.</li>
 *   <li>{@link OAuth2TokenCustomizer} — injects the {@code authorities} claim into access tokens
 *       and id_tokens, and pins the {@code kid} JWS header to the most-recently-created key pair.</li>
 * </ol>
 */
@Component
public class RsaKeyPairRepositoryJWKSource
        implements JWKSource<SecurityContext>, OAuth2TokenCustomizer<JwtEncodingContext> {

    private final RsaKeyPairRepository keyPairRepository;

    public RsaKeyPairRepositoryJWKSource(RsaKeyPairRepository keyPairRepository) {
        this.keyPairRepository = keyPairRepository;
    }

    // -------------------------------------------------------------------------
    // OAuth2TokenCustomizer — called before each JWT is signed
    // -------------------------------------------------------------------------

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        // Inject user authorities into access tokens and id_tokens
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            Set<String> authorities = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("authorities", authorities);
        }

        // Pin the JWS kid header to the most-recently-created key pair
        List<RsaKeyPairRepository.RsaKeyPair> keyPairs = this.keyPairRepository.findKeyPairs();
        if (!keyPairs.isEmpty()) {
            context.getJwsHeader().keyId(keyPairs.get(0).id());
        }
    }

    // -------------------------------------------------------------------------
    // JWKSource — called by NimbusJwtEncoder to sign tokens
    // -------------------------------------------------------------------------

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
        List<RsaKeyPairRepository.RsaKeyPair> keyPairs = this.keyPairRepository.findKeyPairs();
        List<JWK> result = new ArrayList<>(keyPairs.size());
        for (RsaKeyPairRepository.RsaKeyPair keyPair : keyPairs) {
            RSAKey rsaKey = new RSAKey.Builder(keyPair.publicKey())
                    .privateKey(keyPair.privateKey())
                    .keyID(keyPair.id())
                    .build();
            if (jwkSelector.getMatcher().matches(rsaKey)) {
                result.add(rsaKey);
            }
        }
        return result;
    }
}
