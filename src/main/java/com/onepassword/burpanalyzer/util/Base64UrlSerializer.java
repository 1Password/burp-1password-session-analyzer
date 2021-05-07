package com.onepassword.burpanalyzer.util;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;

public class Base64UrlSerializer extends JsonSerializer<byte[]> {
    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        final var result = customEncodeBase64Url(value);
        if(result != null) {
            gen.writeString(result);
        } else {
            throw new IOException("Failed to encode base64.");
        }
    }

    private static String customEncodeBase64Url(byte[] input) {
        final var builder = new StringBuilder();
        int intermediateData = 0;

        for(int index = 0; index < input.length; index++) {
            // The "sub-index", the position of the byte
            // within the group of 3 bytes
            final int position = index % 3;

            // Shift the byte left 16, 8, or 0 bits,
            // then OR it into place in the 24-bit group
            final int byteVal = ((int) input[index]) & 0xFF; // Java doesn't have unsigned bytes, so we force that to happen
            intermediateData |= byteVal << ((16 >>> position) & 24);

            // If it's the last byte in the set of three,
            // or if it's the last byte of the whole array, build the string
            if(position == 2 || index == input.length - 1) {
                // Split the 24-bit value into four 6-bit values,
                // each representing a base64url character,
                // and retrieve the ASCII char code for each character,
                // then annex the four characters to the result
                builder.append(new char[] {
                    mapBase64UrlIndexToASCII((intermediateData >>> 18) & 63),
                    mapBase64UrlIndexToASCII((intermediateData >>> 12) & 63),
                    mapBase64UrlIndexToASCII((intermediateData >>> 6) & 63),
                    mapBase64UrlIndexToASCII((intermediateData & 63))
                });

                // Reset the 24-bit int for the next group of 3 bytes
                intermediateData = 0;
            }
        }

        // Remove extra bytes from the end
        final int paddingLength = (3 - (input.length % 3)) % 3;
        return builder.substring(0, builder.length() - paddingLength);
    }

    private static char mapBase64UrlIndexToASCII(int index) {
        int codepoint;

        if(index < 26) {
            // Shift capital letters from [0-25] to [65-90]
            codepoint = index + 65;
        } else if(index < 52) {
            // Shift lowercase letters from [26-51] to [97-122]
            codepoint = index + 71;
        } else if(index < 62) {
            // Shift numbers from [52-61] to [48-57]
            codepoint = index - 4;
        } else if(index == 62) {
            // Shift "-" from 62 to 45.
            codepoint = 45;
        } else {
            // Shift "_" from 63 to 95.
            codepoint = 95;
        }

        final var chars = Character.toChars(codepoint);

        if(chars.length != 1) {
            throw new IllegalArgumentException("Unable to decode base64 index to a single character.");
        }

        return chars[0];
    }
}
