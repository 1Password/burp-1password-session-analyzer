package com.onepassword.burpanalyzer.util;

import java.util.List;
import java.util.Optional;

public interface OnePasswordHeaders {
    String SESSION_HEADER_NAME = "X-AgileBits-Session-ID";
    String MAC_HEADER_NAME = "X-AgileBits-MAC";

    static Optional<String> parseSessionIdFromHeaders(List<String> headers) {
        return headers.stream()
            .filter(header -> header.toLowerCase().startsWith(OnePasswordHeaders.SESSION_HEADER_NAME.toLowerCase()))
            .findFirst()
            .map(header -> header.split(":", 2))
            .filter(split -> split.length == 2)
            .map(split -> split[1].trim());
    }

    static Optional<Integer> parseRequestIdFromHeaders(List<String> headers) {
        return headers.stream()
            .filter(header -> header.toLowerCase().startsWith(OnePasswordHeaders.MAC_HEADER_NAME.toLowerCase()))
            .findFirst()
            .map(header -> header.split(":", 2))
            .filter(headerSplit -> headerSplit.length == 2)
            .map(headerSplit -> headerSplit[1].trim().split("\\|"))
            .filter(macSplit -> macSplit.length == 3)
            .map(macSplit -> macSplit[1])
            .flatMap(requestIdStr -> {
                try {
                    return Optional.of(Integer.valueOf(requestIdStr));
                } catch (NumberFormatException e) {
                    return Optional.empty();
                }
            });

    }

    static boolean isOnePasswordRequest(List<String> headers) {
        return headers.stream().anyMatch(header -> header.toLowerCase().startsWith(OnePasswordHeaders.MAC_HEADER_NAME.toLowerCase()));
    }

    static boolean isOnePasswordResponse(List<String> headers) {
        return headers.stream().anyMatch(header -> header.startsWith("Content-Security-Policy: ") && header.contains("c.1password.com"));
    }
}
