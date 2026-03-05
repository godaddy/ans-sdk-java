package com.godaddy.ans.sdk.exception;

/**
 * Exception thrown when a requested resource is not found.
 *
 * <p>This exception corresponds to HTTP 404 (Not Found) responses
 * and indicates that the requested agent or resource does not exist.</p>
 */
public class AnsNotFoundException extends AnsException {

    private final String resourceType;
    private final String resourceId;

    /**
     * Creates a new not found exception with the specified message.
     *
     * @param message the error message
     */
    public AnsNotFoundException(String message) {
        this(message, null, null);
    }

    /**
     * Creates a new not found exception for a specific resource.
     *
     * @param resourceType the type of resource (e.g., "Agent")
     * @param resourceId the ID of the resource that was not found
     */
    public AnsNotFoundException(String resourceType, String resourceId) {
        super(resourceType + " not found: " + resourceId);
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }

    /**
     * Creates a new not found exception with all parameters.
     *
     * @param message the error message
     * @param resourceType the type of resource
     * @param resourceId the ID of the resource
     */
    public AnsNotFoundException(String message, String resourceType, String resourceId) {
        super(message);
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }

    /**
     * Creates a new not found exception with request ID.
     *
     * @param message the error message
     * @param resourceType the type of resource
     * @param resourceId the ID of the resource
     * @param requestId the request ID from the server response
     */
    public AnsNotFoundException(String message, String resourceType, String resourceId, String requestId) {
        super(message, requestId);
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }

    /**
     * Returns the type of resource that was not found.
     *
     * @return the resource type, or null if not specified
     */
    public String getResourceType() {
        return resourceType;
    }

    /**
     * Returns the ID of the resource that was not found.
     *
     * @return the resource ID, or null if not specified
     */
    public String getResourceId() {
        return resourceId;
    }

    /**
     * Convenience method to get the agent ID if this is an agent not found error.
     *
     * @return the agent ID, or null if not an agent or not specified
     */
    public String getAgentId() {
        if ("Agent".equals(resourceType)) {
            return resourceId;
        }
        return null;
    }
}