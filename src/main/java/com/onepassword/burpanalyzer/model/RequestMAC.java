package com.onepassword.burpanalyzer.model;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

public class RequestMAC {
    public enum VersionIndicator {
        v1("v1");

        public String versionStr;
        private VersionIndicator(String versionStr) { this.versionStr = versionStr; }
    }

    public enum RequestMethod {
        GET, POST, PUT, PATCH, DELETE, HEAD
    }

    private final VersionIndicator versionIndicator;
    private final RequestMethod requestMethod;

    private final String sessionId;
    private final long requestId;

    private final String host;
    private final String uriPath;
    private final String queryString;

    public VersionIndicator getVersionIndicator() {
        return versionIndicator;
    }

    public RequestMethod getRequestMethod() {
        return requestMethod;
    }

    public String getSessionId() {
        return sessionId;
    }

    public long getRequestId() {
        return requestId;
    }

    public String getHost() {
        return host;
    }

    public String getUriPath() {
        return uriPath;
    }

    public String getQueryString() {
        return queryString;
    }

    public RequestMAC(VersionIndicator versionIndicator, RequestMethod requestMethod, String sessionId, long requestId, URL requestUrl) {
        this.versionIndicator = versionIndicator;
        this.requestMethod = requestMethod;
        this.sessionId = sessionId;
        this.requestId = requestId;
        this.host = requestUrl.getHost().toLowerCase(Locale.ROOT);
        if(requestUrl.getPath() != null) {
            // drop leading '/' with Java's horrific IntStream returning String::chars() method
            this.uriPath = requestUrl.getPath().chars()
                    .mapToObj(i -> (char) i)
                    .dropWhile(c -> c == '/')
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();
        } else {
            this.uriPath = "";
        }

        if(requestUrl.getQuery() != null) {
            this.queryString = requestUrl.getQuery();
        } else {
            this.queryString = "";
        }
    }

    public RequestMAC(VersionIndicator versionIndicator, RequestMethod requestMethod, String sessionId, long requestId, String host, String uriPath, String queryString) {
        this.versionIndicator = versionIndicator;
        this.requestMethod = requestMethod;
        this.sessionId = sessionId;
        this.requestId = requestId;
        this.host = host;
        this.uriPath = uriPath;
        this.queryString = queryString;
    }

    private final static String DERIVATION_MESSAGE = "He never wears a Mac, in the pouring rain. Very strange.";

    public Optional<String> generateRequestHeader(byte[] sessionKey) {
        var authString = String.join("|",
            sessionId,
            requestMethod.toString().toUpperCase(Locale.ROOT),
            host + "/" + uriPath + "?" + queryString,
            versionIndicator.versionStr,
            String.valueOf(requestId)
        );

        Mac hmacSHA256forSessionMac;
        try {
            hmacSHA256forSessionMac = Mac.getInstance("HmacSHA256");
        } catch(NoSuchAlgorithmException e) {
            throw new IllegalStateException("Can't find HmacSHA256. Invalid JVM setup.");
        }

        var key = new SecretKeySpec(sessionKey, "HmacSHA256");
        try {
            hmacSHA256forSessionMac.init(key);
        } catch (InvalidKeyException e) {
            return Optional.empty();
        }
        var sessionMACKey = hmacSHA256forSessionMac.doFinal(DERIVATION_MESSAGE.getBytes(StandardCharsets.US_ASCII));

        Mac hmacSHA256forFinalMac;
        try {
            hmacSHA256forFinalMac = Mac.getInstance("HmacSHA256");
        } catch(NoSuchAlgorithmException e) {
            throw new IllegalStateException("Can't find HmacSHA256. Invalid JVM setup.");
        }

        try {
            hmacSHA256forFinalMac.init(new SecretKeySpec(sessionMACKey, "HmacSHA256"));
        } catch (InvalidKeyException e) {
            return Optional.empty();
        }

        byte[] headerMAC = hmacSHA256forFinalMac.doFinal(authString.getBytes(StandardCharsets.UTF_8));
        byte[] headerMACTruncated = Arrays.copyOfRange(headerMAC, 0, 12);

        String macString = Base64.getUrlEncoder().encodeToString(headerMACTruncated);

        return Optional.of(String.join("|",
            versionIndicator.versionStr,
            String.valueOf(requestId),
            macString
        ));
    }
}
