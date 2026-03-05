package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.exception.AnsException;

/**
 * Exception thrown when protocol-level communication fails.
 *
 * <p>This exception is thrown when the connection is established successfully
 * but protocol-level operations fail, such as:</p>
 * <ul>
 *   <li>Invalid response format from the remote agent</li>
 *   <li>Protocol version mismatch</li>
 *   <li>Unsupported operation requested</li>
 *   <li>Request/response serialization failures</li>
 * </ul>
 */
public class ProtocolException extends AnsException {

    private final String protocol;
    private final int statusCode;

    /**
     * Creates a new exception with the specified message.
     *
     * @param message the error message
     */
    public ProtocolException(String message) {
        this(message, null, null, 0, null);
    }

    /**
     * Creates a new exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public ProtocolException(String message, Throwable cause) {
        this(message, cause, null, 0, null);
    }

    /**
     * Creates a new exception with the specified message, protocol, and status code.
     *
     * @param message the error message
     * @param protocol the protocol that failed (e.g., "A2A", "MCP", "HTTP-API")
     * @param statusCode the HTTP status code if applicable
     */
    public ProtocolException(String message, String protocol, int statusCode) {
        this(message, null, protocol, statusCode, null);
    }

    /**
     * Creates a new exception with all parameters.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param protocol the protocol that failed
     * @param statusCode the HTTP status code if applicable
     * @param requestId the request ID if available
     */
    public ProtocolException(String message, Throwable cause, String protocol, int statusCode, String requestId) {
        super(message, cause, requestId);
        this.protocol = protocol;
        this.statusCode = statusCode;
    }

    /**
     * Returns the protocol that failed.
     *
     * @return the protocol name, or null if not specified
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Returns the HTTP status code if applicable.
     *
     * @return the status code, or 0 if not applicable
     */
    public int getStatusCode() {
        return statusCode;
    }
}