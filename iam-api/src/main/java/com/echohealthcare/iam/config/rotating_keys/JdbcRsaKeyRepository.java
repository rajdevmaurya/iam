package com.echohealthcare.iam.config.rotating_keys;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

@Component
public class JdbcRsaKeyRepository implements RsaKeyPairRepository {

    private final JdbcTemplate jdbcTemplate;
    private final RowMapper<RsaKeyPair> keyPairRowMapper;
    private final RsaPublicKeyConverter rsaPublicKeyConverter;
    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;

    public JdbcRsaKeyRepository(
            JdbcTemplate jdbcTemplate,
            RowMapper<RsaKeyPair> keyPairRowMapper,
            RsaPublicKeyConverter rsaPublicKeyConverter,
            RsaPrivateKeyConverter rsaPrivateKeyConverter) {
        this.jdbcTemplate = jdbcTemplate;
        this.keyPairRowMapper = keyPairRowMapper;
        this.rsaPublicKeyConverter = rsaPublicKeyConverter;
        this.rsaPrivateKeyConverter = rsaPrivateKeyConverter;
    }

    @Override
    public List<RsaKeyPair> findKeyPairs() {
        return this.jdbcTemplate.query(
                "SELECT * FROM rsa_key_pairs ORDER BY created DESC",
                this.keyPairRowMapper);
    }

    @Override
    public void delete(String id) {
        this.jdbcTemplate.update("DELETE FROM rsa_key_pairs WHERE id = ?", id);
    }

    @Override
    public void save(RsaKeyPair rsaKeyPair) {
        String sql = "INSERT INTO rsa_key_pairs (id, created, public_key, private_key) VALUES (?, ?, ?, ?)";
        try (ByteArrayOutputStream privateBaos = new ByteArrayOutputStream();
             ByteArrayOutputStream publicBaos = new ByteArrayOutputStream()) {

            this.rsaPrivateKeyConverter.serialize(rsaKeyPair.privateKey(), privateBaos);
            this.rsaPublicKeyConverter.serialize(rsaKeyPair.publicKey(), publicBaos);

            this.jdbcTemplate.update(sql,
                    rsaKeyPair.id(),
                    new Date(rsaKeyPair.created().toEpochMilli()),
                    publicBaos.toString(),
                    privateBaos.toString());

        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to serialize RSA key pair for storage", e);
        }
    }
}
