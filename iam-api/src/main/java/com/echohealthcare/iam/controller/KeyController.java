package com.echohealthcare.iam.controller;

import java.time.Instant;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.echohealthcare.iam.config.rotating_keys.Keys;
import com.echohealthcare.iam.config.rotating_keys.RsaKeyPairRepository;

/**
 * Operational endpoint for RSA key rotation.
 *
 * POST /oauth2/new_jwks  — generates a new 2048-bit RSA key pair, persists it to the
 *                          rsa_key_pairs table, and returns the new key ID.
 *
 * After rotation the new key becomes the signing key for subsequent tokens.
 * Resource servers will pick up the new public key via /oauth2/jwks on their next
 * JWK refresh cycle (typically within minutes).
 *
 * Access is restricted to users with ROLE_ADMIN.
 */
@RestController
public class KeyController {

    private final RsaKeyPairRepository repository;
    private final Keys keys;

    public KeyController(RsaKeyPairRepository repository, Keys keys) {
        this.repository = repository;
        this.keys = keys;
    }

    @GetMapping("/oauth2/new_jwks")
    @PreAuthorize("hasRole('ADMIN')")
    public String generateNewKeyPair() {
        RsaKeyPairRepository.RsaKeyPair keyPair = keys.generateKeyPair(Instant.now());
        this.repository.save(keyPair);
        return keyPair.id();
    }
}
