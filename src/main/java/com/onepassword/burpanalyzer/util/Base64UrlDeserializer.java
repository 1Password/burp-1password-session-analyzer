package com.onepassword.burpanalyzer.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.Base64;

public class Base64UrlDeserializer extends JsonDeserializer<byte[]> {
    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        if(p.hasCurrentToken()) {
            var b64 = p.getText();
            if(b64 == null || b64.isEmpty()) {
                throw new IOException("Empty string");
            }
            try {
                return Base64.getUrlDecoder().decode(b64);
            } catch (IllegalArgumentException e) {
                throw new IOException("Not valid base64 URL");
            }
        }
        throw new IOException("Empty value");
    }
}

