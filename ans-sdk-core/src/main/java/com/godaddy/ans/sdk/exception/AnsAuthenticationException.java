package com.godaddy.ans.sdk.exception;

/**
 * Exception thrown when authentication fails.
 *
 * <p>This exception indicates that the provided credentials are invalid,
 * expired, or insufficient for the requested operation.</p>
 *
 * <p>Common causes include:</p>
 * <ul>
 *   <li>Expired JWT token</li>
 *   <li>Invalid JWT token format</li>
 *   <li>Invalid API key or secret</li>
 *   <li>Missing credentials</li>
 * </ul>
 */
public class AnsAuthenticationException extends AnsException {

    /**
     * Creates a new authentication exception with the specified message.
     *
     * @param message the error message
     */
    public AnsAuthenticationException(String message) {
        super(message);
    }

    /**
     * Creates a new authentication exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public AnsAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a new authentication exception with all parameters.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param requestId the request ID from the server response
     */
    public AnsAuthenticationException(String message, Throwable cause, String requestId) {
        super(message, cause, requestId);
    }
}