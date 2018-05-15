package com.frankmoley.utilities.crypto.exception;

/**
 * @author Frank P. Moley III.
 */
public class ProviderBasedException extends RuntimeException {
    public ProviderBasedException() {
        super();
    }

    public ProviderBasedException(String message) {
        super(message);
    }

    public ProviderBasedException(String message, Throwable cause) {
        super(message, cause);
    }

    public ProviderBasedException(Throwable cause) {
        super(cause);
    }
}
