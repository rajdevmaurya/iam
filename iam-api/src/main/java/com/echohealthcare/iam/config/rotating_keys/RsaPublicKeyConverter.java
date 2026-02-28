package com.echohealthcare.iam.config.rotating_keys;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

@Component
class RsaPublicKeyConverter implements Serializer<RSAPublicKey>, Deserializer<RSAPublicKey> {

    private final TextEncryptor textEncryptor;

    RsaPublicKeyConverter(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    @Override
    public RSAPublicKey deserialize(InputStream inputStream) throws IOException {
        try {
            String pem = this.textEncryptor.decrypt(
                    FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
            String publicKeyPEM = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");
            byte[] encoded = Base64.getMimeDecoder().decode(publicKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to deserialize RSA public key", ex);
        }
    }

    @Override
    public void serialize(RSAPublicKey key, OutputStream outputStream) throws IOException {
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(key.getEncoded());
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(x509.getEncoded())
                + "\n-----END PUBLIC KEY-----";
        outputStream.write(this.textEncryptor.encrypt(pem).getBytes());
    }
}
