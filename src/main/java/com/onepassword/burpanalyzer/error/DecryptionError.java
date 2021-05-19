package com.onepassword.burpanalyzer.error;

public enum DecryptionError implements BaseError {
    INVALID_SESSION_KEY("Provided session key can't decrypt this message."),
    INVALID_JVM_SETUP("There was a failure setting up expected Java cryptography modules.");

    private final String readable;
    DecryptionError(String readable) { this.readable = readable; }
    @Override
    public String getReadableError() {
        return readable;
    }
}
