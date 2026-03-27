package com.godaddy.ans.sdk.transparency.scitt;

/**
 * Exception thrown when parsing SCITT artifacts (receipts, status tokens) fails.
 */
public class ScittParseException extends Exception {

    /**
     * Creates a new parse exception with the specified message.
     *
     * @param message the error message
     */
    public ScittParseException(String message) {
        super(message);
    }

    /**
     * Creates a new parse exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public ScittParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
