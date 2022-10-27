package com.onepassword.burpanalyzer.processing;

public enum SessionKeyParsingError implements BaseError {
    EMPTY("Session key is not provided."),
    INVALID_LENGTH("Session key must be exactly length 43."),
    INVALID_BASE64_URL("Session key is invalid base64url."),
    FAILURE_TO_RETRIEVE("Could not read session key from UI.");


    SessionKeyParsingError(String readable) { this.readable = readable; };
    private String readable;
    @Override
    public String getReadableError() {
        return readable;
    }
}
