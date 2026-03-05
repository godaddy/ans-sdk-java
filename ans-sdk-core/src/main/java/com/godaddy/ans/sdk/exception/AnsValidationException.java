package com.godaddy.ans.sdk.exception;

import java.util.Collections;
import java.util.Map;

/**
 * Exception thrown when request validation fails.
 *
 * <p>This exception corresponds to HTTP 422 (Unprocessable Entity) responses
 * and indicates that the request parameters did not pass validation.</p>
 *
 * <p>The exception includes field-level error details when available,
 * accessible via {@link #getFieldErrors()}.</p>
 */
public class AnsValidationException extends AnsException {

    private final Map<String, String> fieldErrors;

    /**
     * Creates a new validation exception with the specified message.
     *
     * @param message the error message
     */
    public AnsValidationException(String message) {
        this(message, Collections.emptyMap());
    }

    /**
     * Creates a new validation exception with the specified message and field errors.
     *
     * @param message the error message
     * @param fieldErrors map of field names to error messages
     */
    public AnsValidationException(String message, Map<String, String> fieldErrors) {
        super(message);
        this.fieldErrors = fieldErrors != null ? Map.copyOf(fieldErrors) : Collections.emptyMap();
    }

    /**
     * Creates a new validation exception with all parameters.
     *
     * @param message the error message
     * @param fieldErrors map of field names to error messages
     * @param requestId the request ID from the server response
     */
    public AnsValidationException(String message, Map<String, String> fieldErrors, String requestId) {
        super(message, requestId);
        this.fieldErrors = fieldErrors != null ? Map.copyOf(fieldErrors) : Collections.emptyMap();
    }

    /**
     * Returns field-level validation errors.
     *
     * <p>The map keys are field names and values are error messages
     * describing why validation failed for that field.</p>
     *
     * @return immutable map of field errors, never null
     */
    public Map<String, String> getFieldErrors() {
        return fieldErrors;
    }
}