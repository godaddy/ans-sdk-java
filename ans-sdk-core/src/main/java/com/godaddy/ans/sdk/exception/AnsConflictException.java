package com.godaddy.ans.sdk.exception;

/**
 * Exception thrown when a resource conflict occurs.
 *
 * <p>This exception corresponds to HTTP 409 (Conflict) responses
 * and typically indicates that the resource already exists or
 * there is a conflicting operation in progress.</p>
 */
public class AnsConflictException extends AnsException {

    /**
     * Creates a new conflict exception with the specified message.
     *
     * @param message the error message
     */
    public AnsConflictException(String message) {
        super(message);
    }

    /**
     * Creates a new conflict exception with all parameters.
     *
     * @param message the error message
     * @param requestId the request ID from the server response
     */
    public AnsConflictException(String message, String requestId) {
        super(message, requestId);
    }
}