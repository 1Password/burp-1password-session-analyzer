package com.onepassword.burpanalyzer.error;

public enum RequestMACGenerateError implements BaseError {
    MULTIPLE_SESSION_ID_HEADERS("Found multiple Session ID headers, expecting one."),
    MULTIPLE_SESSION_MAC_HEADERS("Found multiple Session ID headers, expecting one."),
    MISSING_SESSION_ID("Could not find a session ID to use."),
    MISSING_REQUEST_ID("Could not find a request ID to use."),
    MISSING_SESSION_KEY("Session key required to compute a MAC."),
    IS_SERVER_RESPONSE("Request MAC not applicable on server response"),
    INVALID_JVM_SETUP("There was a failure setting up expected Java cryptography modules."),
    INVALID_SESSION_ID_HEADER("Could not parse session ID header"),
    INVALID_MAC_HEADER("Could not parse MAC header to obtain request ID"),
    INVALID_SESSION_KEY("The session key supplied could not be used to generate a MAC."),
    INVALID_DERIVATION_KEY("The derivation key was not usable.");

    RequestMACGenerateError(String readable) { this.readable = readable; }
    private String readable;

    @Override
    public String getReadableError() {
        return readable;
    }

}
