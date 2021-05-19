package com.onepassword.burpanalyzer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.onepassword.burpanalyzer.model.DecryptedPayload;
import com.onepassword.burpanalyzer.model.EncryptedMessage;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptedMessageTests {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    public void successfulUnmarshal() throws JsonProcessingException {
        var encryptedMessage = new EncryptedMessage(
"GBOJATMN3FGLNPXPBMMQXS6XH4",
           EncryptedMessage.Encryption.AES256_GCM,
           EncryptedMessage.ContentType.B5_JWK_JSON,
           Base64.getUrlDecoder().decode("Br3mr9L_-CIsl21k"),
           Base64.getUrlDecoder().decode("5wlJMBi5S8kBoQ_L-XG9N4mNBm4iMxDJ01nguN_FSEZ80XNCi5kWMb6E_WGmdgzE2cqQgCIGa9fUSWsu96VnYEtYGpEHjs20sf7b4axdye03LWH6VNLyypBR0rO02t_9mQaWaddf-zxWqDk9XhQVYe8xcv6vtcYVqRVc4GnqkBGtqMTttRcAey5FgaX6VVGgIRR3UtDMu0htrpJY69ZhdJpmS9ux6yyd-JIi3f82ki1AiaVOKjV39D_snNJYl-789Lxxc0BFCghwMtQmozv2H4QEWl2pCq3VrPQppHbOV69BwRJjKZ1c9eH22Y-Q4Y2jIG17iCqnp1yFXu-alS2czxi7ASNGP0Bkv41RG_8Fvyaa8BxDEiETNTI3JBZliWsj-7nsDBSkrJbGZJDhAgN3pJgG0TIFedtyzeS4fEzvLwC-zAP2qmfQLsWGFJWmz_QVZAyK96fohD2yy1GaifM0jlIPQAFDI4jQAgXAG2KSJpqQrNE1oJ3FzWZVRCMvn3ik2SPDJbgACv_v7XnXP7iIosAjK40V6w8I7_1WvvjeNCRld9cpHtqHP7tn9SWYOm8WtAnZuiS_b55psLR4zdFez8rXOg6_dVZHcGEsWKvf6Zqv7LjzsQQrN_SCe7Qj")
        );

        var jsonInput = "{" +
            "\"kid\":\"GBOJATMN3FGLNPXPBMMQXS6XH4\"," +
            "\"enc\":\"A256GCM\"," +
            "\"cty\":\"b5+jwk+json\"," +
            "\"iv\":\"Br3mr9L_-CIsl21k\"," +
            "\"data\":\"5wlJMBi5S8kBoQ_L-XG9N4mNBm4iMxDJ01nguN_FSEZ80XNCi5kWMb6E_WGmdgzE2cqQgCIGa9fUSWsu96VnYEtYGpEHjs20sf7b4axdye03LWH6VNLyypBR0rO02t_9mQaWaddf-zxWqDk9XhQVYe8xcv6vtcYVqRVc4GnqkBGtqMTttRcAey5FgaX6VVGgIRR3UtDMu0htrpJY69ZhdJpmS9ux6yyd-JIi3f82ki1AiaVOKjV39D_snNJYl-789Lxxc0BFCghwMtQmozv2H4QEWl2pCq3VrPQppHbOV69BwRJjKZ1c9eH22Y-Q4Y2jIG17iCqnp1yFXu-alS2czxi7ASNGP0Bkv41RG_8Fvyaa8BxDEiETNTI3JBZliWsj-7nsDBSkrJbGZJDhAgN3pJgG0TIFedtyzeS4fEzvLwC-zAP2qmfQLsWGFJWmz_QVZAyK96fohD2yy1GaifM0jlIPQAFDI4jQAgXAG2KSJpqQrNE1oJ3FzWZVRCMvn3ik2SPDJbgACv_v7XnXP7iIosAjK40V6w8I7_1WvvjeNCRld9cpHtqHP7tn9SWYOm8WtAnZuiS_b55psLR4zdFez8rXOg6_dVZHcGEsWKvf6Zqv7LjzsQQrN_SCe7Qj\"" +
        "}";

        var unmarshalled = mapper.readValue(jsonInput, EncryptedMessage.class);

        Assert.assertEquals(encryptedMessage, unmarshalled);
    }

    @Test(expected = JsonProcessingException.class)
    public void unmarshalUnknownEnc() throws JsonProcessingException {
        var jsonInput = "{" +
                "\"kid\":\"GBOJATMN3FGLNPXPBMMQXS6XH4\"," +
                "\"enc\":\"3DES\"," +
                "\"cty\":\"b5+jwk+json\"," +
                "\"iv\":\"Br3mr9L_-CIsl21k\"," +
                "\"data\":\"5wlJMBi5S8kBoQ_L-XG9N4mNBm4iMxDJ01nguN_FSEZ80XNCi5kWMb6E_WGmdgzE2cqQgCIGa9fUSWsu96VnYEtYGpEHjs20sf7b4axdye03LWH6VNLyypBR0rO02t_9mQaWaddf-zxWqDk9XhQVYe8xcv6vtcYVqRVc4GnqkBGtqMTttRcAey5FgaX6VVGgIRR3UtDMu0htrpJY69ZhdJpmS9ux6yyd-JIi3f82ki1AiaVOKjV39D_snNJYl-789Lxxc0BFCghwMtQmozv2H4QEWl2pCq3VrPQppHbOV69BwRJjKZ1c9eH22Y-Q4Y2jIG17iCqnp1yFXu-alS2czxi7ASNGP0Bkv41RG_8Fvyaa8BxDEiETNTI3JBZliWsj-7nsDBSkrJbGZJDhAgN3pJgG0TIFedtyzeS4fEzvLwC-zAP2qmfQLsWGFJWmz_QVZAyK96fohD2yy1GaifM0jlIPQAFDI4jQAgXAG2KSJpqQrNE1oJ3FzWZVRCMvn3ik2SPDJbgACv_v7XnXP7iIosAjK40V6w8I7_1WvvjeNCRld9cpHtqHP7tn9SWYOm8WtAnZuiS_b55psLR4zdFez8rXOg6_dVZHcGEsWKvf6Zqv7LjzsQQrN_SCe7Qj\"" +
                "}";

        mapper.readValue(jsonInput, EncryptedMessage.class);
    }

    @Test(expected = JsonProcessingException.class)
    public void unmarshalBadlyEncoded() throws JsonProcessingException {
        var jsonInput = "{" +
            "\"kid\":\"GBOJATMN3FGLNPXPBMMQXS6XH4\"," +
            "\"enc\":\"A256GCM\"," +
            "\"cty\":\"b5+jwk+json\"," +
            "\"iv\":\"Br3mr9L+/CIsl21k\"," +
            "\"data\":\"5wlJMBi5S8kBoQ_L-XG9N4mNBm4iMxDJ01nguN_FSEZ80XNCi5kWMb6E_WGmdgzE2cqQgCIGa9fUSWsu96VnYEtYGpEHjs20sf7b4axdye03LWH6VNLyypBR0rO02t_9mQaWaddf-zxWqDk9XhQVYe8xcv6vtcYVqRVc4GnqkBGtqMTttRcAey5FgaX6VVGgIRR3UtDMu0htrpJY69ZhdJpmS9ux6yyd-JIi3f82ki1AiaVOKjV39D_snNJYl-789Lxxc0BFCghwMtQmozv2H4QEWl2pCq3VrPQppHbOV69BwRJjKZ1c9eH22Y-Q4Y2jIG17iCqnp1yFXu-alS2czxi7ASNGP0Bkv41RG_8Fvyaa8BxDEiETNTI3JBZliWsj-7nsDBSkrJbGZJDhAgN3pJgG0TIFedtyzeS4fEzvLwC-zAP2qmfQLsWGFJWmz_QVZAyK96fohD2yy1GaifM0jlIPQAFDI4jQAgXAG2KSJpqQrNE1oJ3FzWZVRCMvn3ik2SPDJbgACv_v7XnXP7iIosAjK40V6w8I7_1WvvjeNCRld9cpHtqHP7tn9SWYOm8WtAnZuiS_b55psLR4zdFez8rXOg6_dVZHcGEsWKvf6Zqv7LjzsQQrN_SCe7Qj\"" +
        "}";

        mapper.readValue(jsonInput, EncryptedMessage.class);
    }

    @Test
    public void successfulDecryptRequest() {
        var encryptedMessage = new EncryptedMessage(
            "HJM32R3ZHFD6HCXYIEEXSM7EBA",
            EncryptedMessage.Encryption.AES256_GCM,
            EncryptedMessage.ContentType.B5_JWK_JSON,
            Base64.getUrlDecoder().decode("7CLCnKLlFzakf_K4"),
            Base64.getUrlDecoder().decode("VvCwMKlCsazav1NNKH2n7x1GSVLe5WEH4ydL4Mpv3LpSe6sd3XR5KWK2OFwgCQ9RkU95gl5g_pLLkfgv9xKZvX7u9c2SrIo1l_owHd2t04ga31z-XfwioCtX2U_zG4GQd0nOa7ds-uOqjNHrP8hA5Wof21g5L6mHAClRzT0kfCX949LDNNDGqbRqZUj0g4R0s6tJ-RQsA7A2BxCKxVvxemyDAE1tuM6gdSuawbUrRmtXbDaItG-kG7Xmz6o4YsF2Y1xAw3I1BiFy9J9wkTZ5S_ORFZKQ2A8JzTxuyR1ou3WvxW8IpVZDKLgpvrjfYl2RSWwKqfASnTaeBShPn5xCMtPPZydm_j_BQ5isxxAqBp9gWSwV2QAowtAm2jQXQ2K27vCeI1N4q6mpMQ2s7t5kdW_gen7be7HcfPH_i921et1aM2uVleCmd-zYUhrahOS4anxYcKsJTiGll_x0yEBlfVwRrN7M5Sr6-taWuVb8OvvbzPi2ShssJNWEf-FsSq6WMNdGJgc2cE2AFcZJIc8GFwLyoS_z203nqO5zVlFbnD_4_rph22tbids")
        );
        var sessionKey = Base64.getUrlDecoder().decode("wA7-vBGaq2-CJKvpXm_nmo4Xab0wScgibk_GCjhZfNE");

        var decryptedJson = "{\"sessionID\":\"HJM32R3ZHFD6HCXYIEEXSM7EBA\",\"clientVerifyHash\":\"fNLywld9ZIMgv1tEyO2DRTtqZ8shnvBEvjm_kEQDjLM\",\"client\":\"1Password for Web/938\",\"device\":{\"uuid\":\"x6w4d6q5sletp2udhklafgu3zy\",\"clientName\":\"1Password for Web\",\"clientVersion\":\"938\",\"name\":\"Firefox\",\"model\":\"84.0\",\"osName\":\"MacOSX\",\"osVersion\":\"10.16\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0\"}}";
        var plaintextMessage = new DecryptedPayload(decryptedJson.getBytes(StandardCharsets.UTF_8));

        var decryptedMessageOpt = encryptedMessage.decrypt(sessionKey);
        Assert.assertTrue("Encrypted message must successfully decrypt", decryptedMessageOpt.isRight());
        Assert.assertEquals("Decrypted messages must be equal", plaintextMessage, decryptedMessageOpt.get());
    }

    @Test
    public void successfulDecryptResponse() {
        var encryptedMessage = new EncryptedMessage(
            "YKQRP2M3HZFPZDNXTHQBYFPB5M",
            EncryptedMessage.Encryption.AES256_GCM,
            EncryptedMessage.ContentType.B5_JWK_JSON,
            Base64.getUrlDecoder().decode("tYENu1VjK9bH7Ppn"),
            Base64.getUrlDecoder().decode("ajyndPzqt8mnc2R4x_ZGJSmRY6qqbOKKiEljvvNce1xtHNmc_jdbm5oBbQ==")
        );
        var sessionKey = Base64.getUrlDecoder().decode("6fsZq-Md2jvAM7Bk8qLv0z59y68np5IxLK4RLgI_zog");

        var decryptedJson = "{\"users\":[],\"totalCount\":0}";

        var plaintextMessage = new DecryptedPayload(decryptedJson.getBytes(StandardCharsets.UTF_8));

        var decryptedMessageOpt = encryptedMessage.decrypt(sessionKey);
        Assert.assertTrue("Encrypted message must successfully decrypt", decryptedMessageOpt.isRight());
        Assert.assertEquals("Decrypted messages must be equal", decryptedMessageOpt.get(), plaintextMessage);
    }

    @Test
    public void successfulEncryptRequest() throws JsonProcessingException {
        var decryptedJson = "{\"sessionID\":\"HJM32R3ZHFD6HCXYIEEXSM7EBA\",\"clientVerifyHash\":\"fNLywld9ZIMgv1tEyO2DRTtqZ8shnvBEvjm_kEQDjLM\",\"client\":\"1Password for Web/938\",\"device\":{\"uuid\":\"x6w4d6q5sletp2udhklafgu3zy\",\"clientName\":\"1Password for Web\",\"clientVersion\":\"938\",\"name\":\"Firefox\",\"model\":\"84.0\",\"osName\":\"MacOSX\",\"osVersion\":\"10.16\",\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0\"}}";
        var plaintextMessage = new DecryptedPayload(decryptedJson.getBytes(StandardCharsets.UTF_8));
        var sessionKey = Base64.getUrlDecoder().decode("wA7-vBGaq2-CJKvpXm_nmo4Xab0wScgibk_GCjhZfNE");

        var keyIdentifier = "HJM32R3ZHFD6HCXYIEEXSM7EBA";
        var iv = Base64.getUrlDecoder().decode("7CLCnKLlFzakf_K4");

        var intendedMessage = new EncryptedMessage(
            keyIdentifier,
            EncryptedMessage.Encryption.AES256_GCM,
            EncryptedMessage.ContentType.B5_JWK_JSON,
            iv,
            Base64.getUrlDecoder().decode("VvCwMKlCsazav1NNKH2n7x1GSVLe5WEH4ydL4Mpv3LpSe6sd3XR5KWK2OFwgCQ9RkU95gl5g_pLLkfgv9xKZvX7u9c2SrIo1l_owHd2t04ga31z-XfwioCtX2U_zG4GQd0nOa7ds-uOqjNHrP8hA5Wof21g5L6mHAClRzT0kfCX949LDNNDGqbRqZUj0g4R0s6tJ-RQsA7A2BxCKxVvxemyDAE1tuM6gdSuawbUrRmtXbDaItG-kG7Xmz6o4YsF2Y1xAw3I1BiFy9J9wkTZ5S_ORFZKQ2A8JzTxuyR1ou3WvxW8IpVZDKLgpvrjfYl2RSWwKqfASnTaeBShPn5xCMtPPZydm_j_BQ5isxxAqBp9gWSwV2QAowtAm2jQXQ2K27vCeI1N4q6mpMQ2s7t5kdW_gen7be7HcfPH_i921et1aM2uVleCmd-zYUhrahOS4anxYcKsJTiGll_x0yEBlfVwRrN7M5Sr6-taWuVb8OvvbzPi2ShssJNWEf-FsSq6WMNdGJgc2cE2AFcZJIc8GFwLyoS_z203nqO5zVlFbnD_4_rph22tbids")
        );

        var encryptedMessageOpt = plaintextMessage.encrypt(keyIdentifier, iv, sessionKey);
        Assert.assertTrue("Message must successfully encrypt", encryptedMessageOpt.isRight());
        Assert.assertEquals("Encrypted message matches expected", intendedMessage, encryptedMessageOpt.get());

        var plainMapper = new ObjectMapper();
        var expectedJson = mapper.readTree("{" +
                "\"kid\": \"HJM32R3ZHFD6HCXYIEEXSM7EBA\",\n" +
                "\"enc\": \"A256GCM\",\n" +
                "\"cty\": \"b5+jwk+json\",\n" +
                "\"iv\": \"7CLCnKLlFzakf_K4\",\n" +
                "\"data\": \"VvCwMKlCsazav1NNKH2n7x1GSVLe5WEH4ydL4Mpv3LpSe6sd3XR5KWK2OFwgCQ9RkU95gl5g_pLLkfgv9xKZvX7u9c2SrIo1l_owHd2t04ga31z-XfwioCtX2U_zG4GQd0nOa7ds-uOqjNHrP8hA5Wof21g5L6mHAClRzT0kfCX949LDNNDGqbRqZUj0g4R0s6tJ-RQsA7A2BxCKxVvxemyDAE1tuM6gdSuawbUrRmtXbDaItG-kG7Xmz6o4YsF2Y1xAw3I1BiFy9J9wkTZ5S_ORFZKQ2A8JzTxuyR1ou3WvxW8IpVZDKLgpvrjfYl2RSWwKqfASnTaeBShPn5xCMtPPZydm_j_BQ5isxxAqBp9gWSwV2QAowtAm2jQXQ2K27vCeI1N4q6mpMQ2s7t5kdW_gen7be7HcfPH_i921et1aM2uVleCmd-zYUhrahOS4anxYcKsJTiGll_x0yEBlfVwRrN7M5Sr6-taWuVb8OvvbzPi2ShssJNWEf-FsSq6WMNdGJgc2cE2AFcZJIc8GFwLyoS_z203nqO5zVlFbnD_4_rph22tbids\"\n" +
            "}");
        var marshalled = mapper.writeValueAsString(encryptedMessageOpt.get());
        var parsed = mapper.readTree(marshalled);

        Assert.assertEquals("Marshalled JSON should match expected JSON", expectedJson, parsed);
    }

    @Test
    public void successfulEncryptResponse() throws JsonProcessingException {
        var decryptedJson = "{\"users\":[],\"totalCount\":0}";
        var plaintextMessage = new DecryptedPayload(decryptedJson.getBytes(StandardCharsets.UTF_8));
        var sessionKey = Base64.getUrlDecoder().decode("6fsZq-Md2jvAM7Bk8qLv0z59y68np5IxLK4RLgI_zog");

        var keyIdentifier = "YKQRP2M3HZFPZDNXTHQBYFPB5M";
        var iv =  Base64.getUrlDecoder().decode("tYENu1VjK9bH7Ppn");

        var intendedMessage = new EncryptedMessage(
            keyIdentifier,
            EncryptedMessage.Encryption.AES256_GCM,
            EncryptedMessage.ContentType.B5_JWK_JSON,
            iv,
            Base64.getUrlDecoder().decode("ajyndPzqt8mnc2R4x_ZGJSmRY6qqbOKKiEljvvNce1xtHNmc_jdbm5oBbQ")
        );

        var encryptedMessageOpt = plaintextMessage.encrypt(keyIdentifier, iv, sessionKey);
        Assert.assertTrue("Message must successfully encrypt", encryptedMessageOpt.isRight());
        Assert.assertEquals("Encrypted message matches expected", intendedMessage, encryptedMessageOpt.get());

        var expectedJson = mapper.readTree("{" +
                "\"kid\": \"YKQRP2M3HZFPZDNXTHQBYFPB5M\",\n" +
                "\"enc\": \"A256GCM\",\n" +
                "\"cty\": \"b5+jwk+json\",\n" +
                "\"iv\": \"tYENu1VjK9bH7Ppn\",\n" +
                "\"data\": \"ajyndPzqt8mnc2R4x_ZGJSmRY6qqbOKKiEljvvNce1xtHNmc_jdbm5oBbQ\"\n" +
            "}");
        var marshalled = mapper.readTree(mapper.writeValueAsString(encryptedMessageOpt.get()));

        Assert.assertEquals("Marshalled JSON should match expected JSON", expectedJson, marshalled);
    }
}
