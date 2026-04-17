package com.godaddy.ans.sdk.transparency.scitt;

/**
 * Exception thrown when fetching SCITT artifacts fails.
 *
 * <p>This exception is thrown when operations like fetching receipts or
 * status tokens from the transparency log encounter errors.</p>
 */
public final class ScittFetchException extends RuntimeException {

    /**
     * The type of artifact that failed to fetch.
     */
    public enum ArtifactType {
        /** SCITT receipt (Merkle inclusion proof) */
        RECEIPT,
        /** Status token (time-bounded status assertion) */
        STATUS_TOKEN,
        /** Public key from TL or RA */
        PUBLIC_KEY
    }

    private final ArtifactType artifactType;
    private final String agentId;

    /**
     * Creates a new ScittFetchException.
     *
     * @param message the error message
     * @param artifactType the type of artifact that failed to fetch
     * @param agentId the agent ID (may be null for public key fetches)
     */
    public ScittFetchException(String message, ArtifactType artifactType, String agentId) {
        super(message);
        this.artifactType = artifactType;
        this.agentId = agentId;
    }

    /**
     * Creates a new ScittFetchException with a cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param artifactType the type of artifact that failed to fetch
     * @param agentId the agent ID (may be null for public key fetches)
     */
    public ScittFetchException(String message, Throwable cause, ArtifactType artifactType, String agentId) {
        super(message, cause);
        this.artifactType = artifactType;
        this.agentId = agentId;
    }

    /**
     * Returns the type of artifact that failed to fetch.
     *
     * @return the artifact type
     */
    public ArtifactType getArtifactType() {
        return artifactType;
    }

    /**
     * Returns the agent ID for which the fetch failed.
     *
     * @return the agent ID, or null for public key fetches
     */
    public String getAgentId() {
        return agentId;
    }
}
