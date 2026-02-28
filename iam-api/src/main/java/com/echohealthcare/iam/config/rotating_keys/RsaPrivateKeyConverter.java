package com.echohealthcare.iam.config.rotating_keys;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

@Component
class RsaPrivateKeyConverter implements Serializer<RSAPrivateKey>, Deserializer<RSAPrivateKey> {

    private final TextEncryptor textEncryptor;

    RsaPrivateKeyConverter(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    @Override
    public RSAPrivateKey deserialize(InputStream inputStream) throws IOException {
        try {
            String pem = this.textEncryptor.decrypt(
                    FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
            String privateKeyPEM = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to deserialize RSA private key", ex);
        }
    }

    @Override
    public void serialize(RSAPrivateKey key, OutputStream outputStream) throws IOException {
        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(key.getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(pkcs8.getEncoded())
                + "\n-----END PRIVATE KEY-----";
        outputStream.write(this.textEncryptor.encrypt(pem).getBytes());
    }
}
