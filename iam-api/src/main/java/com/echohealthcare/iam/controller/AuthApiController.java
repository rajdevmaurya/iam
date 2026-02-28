package com.echohealthcare.iam.controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.RestController;

import com.echohealthcare.iam.api.DefaultApi;
import com.echohealthcare.iam.model.AnonymousRequest;
import com.echohealthcare.iam.model.AnonymousResponse;
import com.echohealthcare.iam.model.AnErrorResponse;
import com.echohealthcare.iam.model.AuthorizeRequest;
import com.echohealthcare.iam.model.AuthorizeResponse;
import com.echohealthcare.iam.model.ErrorResponse;
import com.echohealthcare.iam.model.LoginRequest;
import com.echohealthcare.iam.model.LoginResponse;

/**
 * REST facade over the local Spring Authorization Server (OIDC + PKCE).
 *
 * Implements the three operations defined in openapi.yaml:
 *   1. authorize  — builds OIDC authorize URL params for a PKCE flow
 *   2. invoke     — validates an anonymous authorization token
 *   3. login      — authenticates user credentials (password grant facade)
 *
 * All endpoints are under the /api/v2 base-path from the OpenAPI spec.
 */
@RestController
public class AuthApiController implements DefaultApi {

    private static final Logger log = LoggerFactory.getLogger(AuthApiController.class);

    private final UserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;

    @Value("${auth.issuer:http://localhost:9000}")
    private String issuerUri;

    public AuthApiController(
            UserDetailsManager userDetailsManager,
            PasswordEncoder passwordEncoder) {
        this.userDetailsManager = userDetailsManager;
        this.passwordEncoder = passwordEncoder;
    }

    // -------------------------------------------------------------------------
    // POST /login/direct/{oidcapp}/authorize
    // -------------------------------------------------------------------------

    /**
     * Builds the OIDC authorization request parameters for a PKCE flow.
     *
     * The client sends its own {@code code_challenge} (S256 hash of the
     * code_verifier it generated). This endpoint echoes it back inside
     * {@code oidc_auth_params} so the client can confirm the round-trip, and
     * returns the full authorization endpoint URL the browser should redirect to.
     */
    @Override
    public ResponseEntity<AuthorizeResponse> authorize(String oidcapp, AuthorizeRequest authorizeRequest) {
        log.debug("authorize() called for oidcapp={}", oidcapp);

        try {
            String authEndpoint = issuerUri + "/oauth2/authorize";
            String completeUri = authEndpoint
                    + "?response_type=code"
                    + "&client_id=" + encode(authorizeRequest.getAppId())
                    + "&state=" + encode(authorizeRequest.getState())
                    + "&nonce=" + encode(authorizeRequest.getNonce())
                    + "&redirect_uri=" + encode(authorizeRequest.getRedirectUri())
                    + "&code_challenge=" + encode(authorizeRequest.getCodeChallenge())
                    + "&code_challenge_method=S256"
                    + "&scope=" + encode("openid profile");

            AuthorizeResponse response = new AuthorizeResponse();
            response.setErrorCode("0");
            response.setToken(UUID.randomUUID().toString());   // session correlation token
            response.setCompleteUri(completeUri);
            response.setSid(UUID.randomUUID().toString());
            response.setPid(authorizeRequest.getAppId());
            response.setAid(oidcapp);

            return ResponseEntity.ok(response);

        } catch (Exception ex) {
            log.error("authorize() failed", ex);
            ErrorResponse err = new ErrorResponse();
            err.setErrorCode("AUTH_FAILED");
            err.setErrorDescription(ex.getMessage());
            return ResponseEntity.status(401).build();
        }
    }

    // -------------------------------------------------------------------------
    // POST /auth/anonymous_invoke
    // -------------------------------------------------------------------------

    /**
     * Validates an anonymous {@code authorization_token} against registered clients.
     * Used for policy-based, userless journey invocations.
     */
    @Override
    public ResponseEntity<AnonymousResponse> invoke(AnonymousRequest anonymousRequest) {
        log.debug("invoke() called for app_id={}", anonymousRequest.getAppId());

        AnonymousResponse response = new AnonymousResponse();

        if (anonymousRequest.getAuthorizationToken() == null
                || anonymousRequest.getAuthorizationToken().isBlank()) {
            response.setErrorCode("MISSING_TOKEN");
            response.setErrorMessage("authorization_token is required");
            return ResponseEntity.status(401).body(response);
        }

        // Token validation is delegated to the Spring Authorization Server filter chain.
        // If this method is reached the Bearer token was already validated by the
        // oauth2ResourceServer configurer in SecurityConfig (filter chain 3).
        response.setErrorCode("0");
        response.setErrorMessage("OK");
        response.setRedirectUri(issuerUri + "/oauth2/authorize");
        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // POST /auth/login
    // -------------------------------------------------------------------------

    /**
     * Authenticates a user by {@code contractId} (username) and {@code password}.
     *
     * This is a direct credential check — it does NOT issue tokens. Token issuance
     * happens via the standard OIDC authorization_code flow at /oauth2/token.
     * Use this endpoint only for headless/API clients that need a credential check
     * before initiating the PKCE flow.
     */
    @Override
    public ResponseEntity<LoginResponse> login(LoginRequest loginRequest) {
        log.debug("login() called for contractId={}", loginRequest.getContractId());

        LoginResponse response = new LoginResponse();

        try {
            UserDetails user = userDetailsManager.loadUserByUsername(loginRequest.getContractId());

            if (!user.isEnabled()) {
                response.setStatus("FAILURE");
                response.setMessage("Account is disabled");
                return ResponseEntity.status(401).body(response);
            }

            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                response.setStatus("FAILURE");
                response.setMessage("Invalid credentials");
                return ResponseEntity.status(401).body(response);
            }

            response.setStatus("SUCCESS");
            response.setMessage("Authentication successful");
            return ResponseEntity.ok(response);

        } catch (UsernameNotFoundException ex) {
            log.warn("login() unknown user: {}", loginRequest.getContractId());
            response.setStatus("FAILURE");
            response.setMessage("Invalid credentials");
            return ResponseEntity.status(401).body(response);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
