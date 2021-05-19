package com.onepassword.burpanalyzer.util;

import burp.IRequestInfo;
import com.onepassword.burpanalyzer.model.RequestMAC;

import java.util.Locale;
import java.util.stream.Collectors;

public interface RequestMACParser {
    enum ParseFailure {
        MULTIPLE_SESSION_MAC_HEADERS("Found multiple Session MAC headers, expecting one."),
        MISSING_SESSION_ID("Could not find a session ID to use."),
        MISSING_REQUEST_ID("Could not find a request ID to use."),
        INVALID_SESSION_ID_HEADER("Could not parse session ID header"),
        INVALID_MAC_HEADER("Could not parse MAC header to obtain request ID");

        private final String readableError;

        ParseFailure(String readableError) {
            this.readableError = readableError;
        }

        public String getReadableError() {
            return readableError;
        }
    }


    class Result {
        private final RequestMAC requestMAC;
        private final ParseFailure parseFailure;

        public Result(RequestMAC requestMAC) {
            this.requestMAC = requestMAC;
            this.parseFailure = null;
        }

        public Result(ParseFailure parseFailure) {
            this.requestMAC = null;
            this.parseFailure = parseFailure;
        }

        public boolean didSucceed() {
            return requestMAC != null;
        }

        public RequestMAC getRequestMAC() {
            return requestMAC;
        }

        public ParseFailure getParseFailure() {
            return parseFailure;
        }
    }

    static RequestMACParser.Result parseRequestMac(IRequestInfo requestInfo) {
        final var macVersion = RequestMAC.VersionIndicator.v1;
        final var method = requestInfo.getMethod().toUpperCase(Locale.ROOT);
        final var requestMethod = RequestMAC.RequestMethod.valueOf(method);

        final var sessionIdHeaders = requestInfo.getHeaders().stream()
                .filter(header -> header.toLowerCase().startsWith(OnePasswordHeaders.SESSION_HEADER_NAME.toLowerCase()))
                .collect(Collectors.toSet());

        if(sessionIdHeaders.size() > 1) {
            return new Result(ParseFailure.MULTIPLE_SESSION_MAC_HEADERS);
        }

        if(sessionIdHeaders.size() == 0 || sessionIdHeaders.iterator().next() == null) {
            return new Result(ParseFailure.MISSING_SESSION_ID);
        }

        final var sessionIdHeader = sessionIdHeaders.iterator().next();
        final var splitSessionIdHeader = sessionIdHeader.split(":");

        if(splitSessionIdHeader.length != 2) {
            return new Result(ParseFailure.INVALID_SESSION_ID_HEADER);
        }
        final var sessionId = splitSessionIdHeader[1].strip();

        final var macHeaders = requestInfo.getHeaders().stream()
                .filter(header -> header.toLowerCase().startsWith(OnePasswordHeaders.MAC_HEADER_NAME.toLowerCase()))
                .collect(Collectors.toSet());

        if(macHeaders.size() > 1) {
            return new Result(ParseFailure.MULTIPLE_SESSION_MAC_HEADERS);
        }

        if(macHeaders.size() == 0 || macHeaders.iterator().next() == null) {
            return new Result(ParseFailure.MISSING_REQUEST_ID);
        }

        final var macHeader = macHeaders.iterator().next();
        final var macHeaderSplit = macHeader.split(":");
        if(macHeaderSplit.length != 2) {
            return new Result(ParseFailure.INVALID_MAC_HEADER);
        }
        final var macString = macHeaderSplit[1];

        final var macStringSplit = macString.split("\\|");
        if(macStringSplit.length != 3) {
            return new Result(ParseFailure.INVALID_MAC_HEADER);
        }

        final var requestIdStr = macStringSplit[1];
        final long requestId;
        try {
            requestId = Long.parseLong(requestIdStr);
        } catch(NumberFormatException e) {
            return new Result(ParseFailure.INVALID_MAC_HEADER);
        }

        return new Result(
            new RequestMAC(macVersion, requestMethod, sessionId, requestId, requestInfo.getUrl())
        );
    }

}
