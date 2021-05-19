package com.onepassword.burpanalyzer.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.onepassword.burpanalyzer.error.DecryptionError;
import com.onepassword.burpanalyzer.util.Base64UrlDeserializer;
import com.onepassword.burpanalyzer.util.Base64UrlSerializer;
import io.vavr.control.Either;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

public class EncryptedMessage {
    public enum Encryption { @JsonProperty("A256GCM") AES256_GCM };
    public enum ContentType { @JsonProperty("b5+jwk+json") B5_JWK_JSON };

    @JsonProperty("kid")
    private String keyIdentifier;

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    @JsonProperty("enc")
    private Encryption encryption;

    @JsonProperty("cty")
    private ContentType contentType;

    public byte[] getIv() {
        return iv;
    }

    @JsonProperty("iv")
    @JsonSerialize(using=Base64UrlSerializer.class)
    @JsonDeserialize(using=Base64UrlDeserializer.class)
    private byte[] iv;

    @JsonProperty("data")
    @JsonSerialize(using=Base64UrlSerializer.class)
    @JsonDeserialize(using=Base64UrlDeserializer.class)
    private byte[] data;

    private boolean isEmpty = false;

    @Override
    public String toString() {
        if (isEmpty) {
            return "EncryptedMessage{empty}";
        } else {
            return "EncryptedMessage{" +
                    "keyIdentifier='" + keyIdentifier + '\'' +
                    ", encryption=" + encryption +
                    ", contentType=" + contentType +
                    ", iv=" + Arrays.toString(iv) +
                    ", data=" + Arrays.toString(data) +
                    '}';
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedMessage that = (EncryptedMessage) o;
        if(isEmpty && that.isEmpty) {
            return true;
        } else {
            return Objects.equals(keyIdentifier, that.keyIdentifier) && encryption == that.encryption && contentType == that.contentType && Arrays.equals(iv, that.iv) && Arrays.equals(data, that.data);
        }
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyIdentifier, encryption, contentType);
        result = 31 * result + Arrays.hashCode(iv);
        result = 31 * result + Arrays.hashCode(data);
        return result;
    }

    public EncryptedMessage() {}

    public EncryptedMessage(String keyIdentifier, Encryption encryption, ContentType contentType, byte[] iv, byte[] data) {
        this.keyIdentifier = keyIdentifier;
        this.encryption = encryption;
        this.contentType = contentType;
        this.iv = iv;
        this.data = data;
    }

    public static EncryptedMessage empty() {
        var res = new EncryptedMessage();
        res.isEmpty = true;
        return res;
    }

    public Either<DecryptionError, DecryptedPayload> decrypt(byte[] sessionKey) {
        if(isEmpty) {
            return Either.right(new DecryptedPayload(new byte[0]));
        }

        Cipher AesGcm;

        try {
            AesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            return Either.left(DecryptionError.INVALID_JVM_SETUP);
        }

        var keySpec = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        var gcmParamSpec = new GCMParameterSpec(128, iv);

        try {
            AesGcm.init(Cipher.DECRYPT_MODE, keySpec, gcmParamSpec);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            return Either.left(DecryptionError.INVALID_SESSION_KEY);
        }

        byte[] output;
        try {
            output = AesGcm.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            return Either.left(DecryptionError.INVALID_SESSION_KEY);
        }

        return Either.right(new DecryptedPayload(output));
    }
}
