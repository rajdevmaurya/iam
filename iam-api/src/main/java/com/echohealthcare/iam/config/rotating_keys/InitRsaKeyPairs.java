package com.echohealthcare.iam.config.rotating_keys;

import java.time.Instant;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Seeds the rsa_key_pairs table with one key pair on first startup.
 * If the table already contains entries (restarting an existing deployment),
 * this is a no-op — existing keys are preserved.
 *
 * To rotate keys at runtime call GET /oauth2/new_jwks (see KeyController).
 */
@Component
public class InitRsaKeyPairs implements ApplicationRunner {

    private final RsaKeyPairRepository repository;
    private final Keys keys;

    public InitRsaKeyPairs(RsaKeyPairRepository repository, Keys keys) {
        this.repository = repository;
        this.keys = keys;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (this.repository.findKeyPairs().isEmpty()) {
            RsaKeyPairRepository.RsaKeyPair keyPair = keys.generateKeyPair(Instant.now());
            this.repository.save(keyPair);
        }
    }
}
