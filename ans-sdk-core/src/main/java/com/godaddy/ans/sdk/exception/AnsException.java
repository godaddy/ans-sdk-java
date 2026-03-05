package com.godaddy.ans.sdk.exception;

/**
 * Base exception for all ANS SDK errors.
 *
 * <p>This exception serves as the root of the ANS SDK exception hierarchy.
 * Catching this exception will catch all SDK-related errors.</p>
 */
public class AnsException extends RuntimeException {

    private final String requestId;

    /**
     * Creates a new exception with the specified message.
     *
     * @param message the error message
     */
    public AnsException(String message) {
        this(message, null, null);
    }

    /**
     * Creates a new exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public AnsException(String message, Throwable cause) {
        this(message, cause, null);
    }

    /**
     * Creates a new exception with the specified message and request ID.
     *
     * @param message the error message
     * @param requestId the request ID from the server response
     */
    public AnsException(String message, String requestId) {
        this(message, null, requestId);
    }

    /**
     * Creates a new exception with all parameters.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param requestId the request ID from the server response
     */
    public AnsException(String message, Throwable cause, String requestId) {
        super(message, cause);
        this.requestId = requestId;
    }

    /**
     * Returns the request ID from the server response, if available.
     *
     * <p>The request ID can be used for debugging and support purposes.</p>
     *
     * @return the request ID, or null if not available
     */
    public String getRequestId() {
        return requestId;
    }
}