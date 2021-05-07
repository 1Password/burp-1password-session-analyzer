package com.onepassword.burpanalyzer.error;

public enum EncryptionError implements BaseError {
    MISSING_SESSION_KEY("No session key available to decrypt with."),
    INVALID_SESSION_KEY("Provided session key is invalid format"),
    INVALID_JVM_SETUP("There was a failure setting up expected Java cryptography modules.");

    EncryptionError(String readable) { this.readable = readable; }
    private String readable;
    @Override
    public String getReadableError() {
        return readable;
    }
}
