package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.exception.AnsException;

/**
 * Exception thrown when a connection to a remote agent fails.
 *
 * <p>This exception can be caused by:</p>
 * <ul>
 *   <li>Network connectivity issues</li>
 *   <li>Agent not responding at the expected endpoint</li>
 *   <li>mTLS handshake failures</li>
 *   <li>Connection timeout</li>
 * </ul>
 */
public class AgentConnectionException extends AnsException {

    private final String targetAgentHost;

    /**
     * Creates a new exception with the specified message.
     *
     * @param message the error message
     */
    public AgentConnectionException(String message) {
        this(message, null, null, null);
    }

    /**
     * Creates a new exception with the specified message and target agent.
     *
     * @param message the error message
     * @param targetAgentHost the target agent host that failed to connect
     */
    public AgentConnectionException(String message, String targetAgentHost) {
        this(message, null, targetAgentHost, null);
    }

    /**
     * Creates a new exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public AgentConnectionException(String message, Throwable cause) {
        this(message, cause, null, null);
    }

    /**
     * Creates a new exception with the specified message, cause, and target agent.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param targetAgentHost the target agent host that failed to connect
     */
    public AgentConnectionException(String message, Throwable cause, String targetAgentHost) {
        this(message, cause, targetAgentHost, null);
    }

    /**
     * Creates a new exception with all parameters.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param targetAgentHost the target agent host that failed to connect
     * @param requestId the request ID if available
     */
    public AgentConnectionException(String message, Throwable cause, String targetAgentHost, String requestId) {
        super(message, cause, requestId);
        this.targetAgentHost = targetAgentHost;
    }

    /**
     * Returns the target agent host that failed to connect.
     *
     * @return the target agent host, or null if not available
     */
    public String getTargetAgentHost() {
        return targetAgentHost;
    }
}
