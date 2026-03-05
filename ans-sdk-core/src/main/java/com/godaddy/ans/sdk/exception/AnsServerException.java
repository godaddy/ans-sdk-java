package com.godaddy.ans.sdk.exception;

/**
 * Exception thrown when the server returns an error response.
 *
 * <p>This exception corresponds to HTTP 5xx responses and indicates
 * a server-side error. These errors are typically transient and may
 * be retried.</p>
 */
public class AnsServerException extends AnsException {

    private final int statusCode;

    /**
     * Creates a new server exception with the specified message.
     *
     * @param message the error message
     */
    public AnsServerException(String message) {
        this(message, 500);
    }

    /**
     * Creates a new server exception with the specified message and status code.
     *
     * @param message the error message
     * @param statusCode the HTTP status code
     */
    public AnsServerException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    /**
     * Creates a new server exception with all parameters.
     *
     * @param message the error message
     * @param statusCode the HTTP status code
     * @param requestId the request ID from the server response
     */
    public AnsServerException(String message, int statusCode, String requestId) {
        super(message, requestId);
        this.statusCode = statusCode;
    }

    /**
     * Creates a new server exception with cause.
     *
     * @param message the error message
     * @param statusCode the HTTP status code
     * @param cause the underlying cause
     * @param requestId the request ID from the server response
     */
    public AnsServerException(String message, int statusCode, Throwable cause, String requestId) {
        super(message, cause, requestId);
        this.statusCode = statusCode;
    }

    /**
     * Returns the HTTP status code.
     *
     * @return the HTTP status code (5xx)
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Alias for {@link #getStatusCode()} for compatibility.
     *
     * @return the HTTP status code
     */
    public int getCode() {
        return statusCode;
    }

    /**
     * Returns whether this error is potentially retryable.
     *
     * <p>Server errors (5xx) are typically transient and may succeed
     * if retried after a delay.</p>
     *
     * @return true if the error may be retryable
     */
    public boolean isRetryable() {
        return statusCode >= 500 && statusCode < 600;
    }
}