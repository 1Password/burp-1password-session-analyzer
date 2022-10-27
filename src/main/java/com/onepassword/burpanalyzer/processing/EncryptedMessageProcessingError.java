package com.onepassword.burpanalyzer.processing;

public enum EncryptedMessageProcessingError implements BaseError {
    EMPTY("No payload was found."),
    INVALID_BODY("Could not parse request body JSON.");

    EncryptedMessageProcessingError(String readable) { this.readable = readable; }
    private String readable;

    @Override
    public String getReadableError() {
        return readable;
    }
}
