package com.godaddy.ans.sdk.transparency;

import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.transparency.model.AgentAuditParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryResponse;
import com.godaddy.ans.sdk.transparency.model.CheckpointResponse;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogAudit;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Client for ANS Transparency Log API operations.
 *
 * <p>The transparency log is a public, append-only record of all agent
 * registrations and state changes. This client provides methods to query
 * the log and retrieve agent registration data.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * TransparencyClient client = TransparencyClient.builder()
 *     .baseUrl("https://transparency.ans.godaddy.com")
 *     .build();
 *
 * // Get current registration
 * TransparencyLog log = client.getAgentTransparencyLog("agent-uuid");
 *
 * // Access V1 payload
 * if (log.isV1()) {
 *     TransparencyLogV1 v1 = log.getV1Payload();
 *     String fingerprint = v1.getAttestations().getServerCert().getFingerprint();
 * }
 *
 * // Or use convenience methods
 * String serverFingerprint = log.getServerCertFingerprint();
 * String identityFingerprint = log.getIdentityCertFingerprint();
 * }</pre>
 */
public final class TransparencyClient {

    /**
     * Default base URL for the transparency log.
     */
    public static final String DEFAULT_BASE_URL = "https://transparency.ans.ote-godaddy.com";

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);

    private final String baseUrl;
    private final TransparencyService service;

    private TransparencyClient(String baseUrl, Duration connectTimeout, Duration readTimeout) {
        this.baseUrl = baseUrl;
        this.service = new TransparencyService(baseUrl, connectTimeout, readTimeout);
    }

    /**
     * Creates a new builder for constructing a TransparencyClient.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a TransparencyClient with default configuration.
     *
     * @return a new TransparencyClient with defaults
     */
    public static TransparencyClient create() {
        return builder().build();
    }

    // ==================== Agent Log Operations (Sync) ====================

    /**
     * Retrieves the current transparency log entry for an agent.
     *
     * <p>This returns the latest registration state including attestations
     * with certificate fingerprints. Use {@link TransparencyLog#getServerCertFingerprint()}
     * or {@link TransparencyLog#getIdentityCertFingerprint()} to access fingerprints.</p>
     *
     * @param agentId the agent's unique identifier (UUID)
     * @return the transparency log entry
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     */
    public TransparencyLog getAgentTransparencyLog(String agentId) {
        return service.getAgentTransparencyLog(agentId);
    }

    /**
     * Retrieves a paginated list of transparency log records for an agent.
     *
     * <p>This returns the audit trail showing all state changes for the agent.</p>
     *
     * @param agentId the agent's unique identifier
     * @param params optional pagination parameters (offset, limit)
     * @return the paginated audit records
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     */
    public TransparencyLogAudit getAgentTransparencyLogAudit(String agentId, AgentAuditParams params) {
        return service.getAgentTransparencyLogAudit(agentId, params);
    }

    /**
     * Retrieves all transparency log records for an agent.
     *
     * @param agentId the agent's unique identifier
     * @return the audit records
     */
    public TransparencyLogAudit getAgentTransparencyLogAudit(String agentId) {
        return getAgentTransparencyLogAudit(agentId, null);
    }

    // ==================== Checkpoint Operations (Sync) ====================

    /**
     * Retrieves the current checkpoint for the transparency log.
     *
     * <p>The checkpoint contains the current root hash and can be used
     * to verify the integrity of the log.</p>
     *
     * @return the current checkpoint
     */
    public CheckpointResponse getCheckpoint() {
        return service.getCheckpoint();
    }

    /**
     * Retrieves a paginated list of historical checkpoints.
     *
     * @param params optional query parameters for filtering and pagination
     * @return the checkpoint history
     */
    public CheckpointHistoryResponse getCheckpointHistory(CheckpointHistoryParams params) {
        return service.getCheckpointHistory(params);
    }

    /**
     * Retrieves checkpoint history with default parameters.
     *
     * @return the checkpoint history
     */
    public CheckpointHistoryResponse getCheckpointHistory() {
        return getCheckpointHistory(null);
    }

    // ==================== Schema Operations (Sync) ====================

    /**
     * Retrieves the JSON schema for a specific transparency log schema version.
     *
     * @param version the schema version (e.g., "V0", "V1")
     * @return the JSON schema as a map
     */
    public Map<String, Object> getLogSchema(String version) {
        return service.getLogSchema(version);
    }

    // ==================== Async Operations ====================

    /**
     * Retrieves the current transparency log entry for an agent asynchronously.
     *
     * @param agentId the agent's unique identifier
     * @return a CompletableFuture with the transparency log entry
     */
    public CompletableFuture<TransparencyLog> getAgentTransparencyLogAsync(String agentId) {
        return CompletableFuture.supplyAsync(() -> getAgentTransparencyLog(agentId), AnsExecutors.sharedIoExecutor());
    }

    /**
     * Retrieves a paginated list of transparency log records asynchronously.
     *
     * @param agentId the agent's unique identifier
     * @param params optional pagination parameters
     * @return a CompletableFuture with the audit records
     */
    public CompletableFuture<TransparencyLogAudit> getAgentTransparencyLogAuditAsync(
            String agentId, AgentAuditParams params) {
        return CompletableFuture.supplyAsync(() -> getAgentTransparencyLogAudit(agentId, params),
                AnsExecutors.sharedIoExecutor());
    }

    /**
     * Retrieves the current checkpoint asynchronously.
     *
     * @return a CompletableFuture with the checkpoint
     */
    public CompletableFuture<CheckpointResponse> getCheckpointAsync() {
        return CompletableFuture.supplyAsync(this::getCheckpoint, AnsExecutors.sharedIoExecutor());
    }

    /**
     * Retrieves checkpoint history asynchronously.
     *
     * @param params optional query parameters
     * @return a CompletableFuture with the checkpoint history
     */
    public CompletableFuture<CheckpointHistoryResponse> getCheckpointHistoryAsync(
            CheckpointHistoryParams params) {
        return CompletableFuture.supplyAsync(() -> getCheckpointHistory(params), AnsExecutors.sharedIoExecutor());
    }

    // ==================== Accessors ====================

    /**
     * Returns the base URL this client is configured to use.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Builder for constructing a TransparencyClient.
     */
    public static final class Builder {

        private String baseUrl = DEFAULT_BASE_URL;
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration readTimeout = DEFAULT_READ_TIMEOUT;

        private Builder() {
        }

        /**
         * Sets the base URL for the transparency log API.
         *
         * @param baseUrl the base URL (default: https://transparency.ans.godaddy.com)
         * @return this builder
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * Sets the connection timeout.
         *
         * @param timeout the connection timeout (default: 10 seconds)
         * @return this builder
         */
        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = timeout;
            return this;
        }

        /**
         * Sets the read timeout.
         *
         * @param timeout the read timeout (default: 30 seconds)
         * @return this builder
         */
        public Builder readTimeout(Duration timeout) {
            this.readTimeout = timeout;
            return this;
        }

        /**
         * Builds the TransparencyClient.
         *
         * @return a new TransparencyClient instance
         */
        public TransparencyClient build() {
            return new TransparencyClient(baseUrl, connectTimeout, readTimeout);
        }
    }
}