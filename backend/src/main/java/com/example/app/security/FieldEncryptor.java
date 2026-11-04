package com.example.app.security;

import com.example.app.config.AppProperties;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Cifrado de campos sensibles en reposo (AES-256-GCM, JCE estandar). La clave viene del entorno/gestor de secretos.
 * El AAD ata el texto cifrado a su fila (no se puede mover el secreto de un usuario a otro).
 */
@Component
public class FieldEncryptor {
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private final SecureRandom random = new SecureRandom();
    private final SecretKeySpec key;

    public FieldEncryptor(AppProperties props) {
        this.key = new SecretKeySpec(Base64.getDecoder().decode(props.crypto().key()), "AES");
    }

    public String encrypt(byte[] plain, String aad) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plain);
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo cifrar", e);
        }
    }

    public byte[] decrypt(String encoded, String aad) {
        try {
            byte[] all = Base64.getDecoder().decode(encoded);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, all, 0, IV_BYTES));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return c.doFinal(all, IV_BYTES, all.length - IV_BYTES);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("No se pudo descifrar", e);   // falla cerrado
        }
    }
}
