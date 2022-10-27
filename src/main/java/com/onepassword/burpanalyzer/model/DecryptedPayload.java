package com.onepassword.burpanalyzer.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.onepassword.burpanalyzer.processing.EncryptionError;
import com.onepassword.burpanalyzer.processing.Result;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class DecryptedPayload {
    private byte[] body;

    public DecryptedPayload(byte[] body) {
        this.body = body;
    }

    public byte[] getBody() {
        return body;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    // DecryptedBody is equal if their JSON is equal if their bodies are valid JSON
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DecryptedPayload that = (DecryptedPayload) o;

        var mapper = new ObjectMapper();

        try {
            var thisJson = mapper.readTree(this.body);
            var thatJson = mapper.readTree(that.body);
            return thisJson.equals(thatJson);
        } catch(IOException e) {
            return Arrays.equals(body, that.body);
        }
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(body);
    }

    public Result<EncryptedMessage, EncryptionError> encrypt(String keyIdentifier, byte[] iv, byte[] sessionKey) {
        Cipher AesGcm;

        try {
            AesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return new Result<>(EncryptionError.INVALID_JVM_SETUP);
        }

        var keySpec = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        var gcmParamSpec = new GCMParameterSpec(128, iv);

        try {
            AesGcm.init(Cipher.ENCRYPT_MODE, keySpec, gcmParamSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            return new Result<>(EncryptionError.INVALID_SESSION_KEY);
        }

        if(body.length == 0) {
            return new Result<>(EncryptedMessage.empty());
        }

        byte[] output;
        try {
            output = AesGcm.doFinal(body);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            return new Result<>(EncryptionError.INVALID_SESSION_KEY);
        }

        return new Result<>(
            new EncryptedMessage(
                keyIdentifier, EncryptedMessage.Encryption.AES256_GCM, EncryptedMessage.ContentType.B5_JWK_JSON, iv, output
            ));
    }
}
