package com.godaddy.ans.sdk.transparency;

import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.transparency.model.AgentAuditParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryResponse;
import com.godaddy.ans.sdk.transparency.model.CheckpointResponse;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogAudit;
import com.godaddy.ans.sdk.transparency.scitt.RefreshDecision;
import com.godaddy.ans.sdk.transparency.scitt.TrustedDomainRegistry;

import java.net.URI;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
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

    /**
     * Default cache TTL for the root public key (24 hours).
     *
     * <p>Root keys rarely change, so a long TTL is appropriate.</p>
     */
    public static final Duration DEFAULT_ROOT_KEY_CACHE_TTL = Duration.ofHours(24);

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);

    private final String baseUrl;
    private final TransparencyService service;

    private TransparencyClient(String baseUrl, Duration connectTimeout, Duration readTimeout,
                               Duration rootKeyCacheTtl) {
        this.baseUrl = baseUrl;
        this.service = new TransparencyService(baseUrl, connectTimeout, readTimeout, rootKeyCacheTtl);
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

    // ==================== SCITT Operations (Sync) ====================

    /**
     * Retrieves the SCITT receipt for an agent.
     *
     * <p>The receipt is a COSE_Sign1 structure containing a Merkle inclusion
     * proof that the agent's registration was recorded in the transparency log.</p>
     *
     * @param agentId the agent's unique identifier
     * @return the raw receipt bytes (COSE_Sign1)
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     */
    public byte[] getReceipt(String agentId) {
        return service.getReceipt(agentId);
    }

    /**
     * Retrieves the status token for an agent.
     *
     * <p>The status token is a COSE_Sign1 structure containing a time-bounded
     * assertion of the agent's current status and valid certificate fingerprints.</p>
     *
     * @param agentId the agent's unique identifier
     * @return the raw status token bytes (COSE_Sign1)
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     */
    public byte[] getStatusToken(String agentId) {
        return service.getStatusToken(agentId);
    }

    /**
     * Invalidates the cached root public keys.
     *
     * <p>Call this method to force the next {@link #getRootKeysAsync()} call to
     * fetch fresh keys from the server. This is useful when you know the
     * root keys have been rotated.</p>
     */
    public void invalidateRootKeyCache() {
        service.invalidateRootKeyCache();
    }

    /**
     * Returns the timestamp when the root key cache was last populated.
     *
     * <p>This can be used to determine if an artifact was issued after the cache
     * was refreshed, which may indicate the artifact was signed with a new key
     * that we don't have yet.</p>
     *
     * @return the cache population timestamp, or {@link Instant#EPOCH} if never populated
     */
    public Instant getCachePopulatedAt() {
        return service.getCachePopulatedAt();
    }

    /**
     * Attempts to refresh the root key cache if the artifact's issued-at timestamp
     * indicates it may have been signed with a new key not yet in our cache.
     *
     * <p>This method performs security checks to prevent cache thrashing attacks:</p>
     * <ul>
     *   <li>Rejects artifacts claiming to be from the future (beyond 60s clock skew)</li>
     *   <li>Rejects artifacts older than our cache (key should already be present)</li>
     *   <li>Enforces a 30-second global cooldown between refresh attempts</li>
     * </ul>
     *
     * <p>Use this method when a key lookup fails during SCITT verification to
     * potentially recover from a key rotation scenario.</p>
     *
     * @param artifactIssuedAt the issued-at timestamp from the SCITT artifact
     * @return the refresh decision indicating whether to retry verification
     */
    public RefreshDecision refreshRootKeysIfNeeded(Instant artifactIssuedAt) {
        return service.refreshRootKeysIfNeeded(artifactIssuedAt);
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

    /**
     * Retrieves the SCITT receipt for an agent asynchronously.
     *
     * <p>This method uses non-blocking I/O and does not occupy a thread pool
     * thread during the HTTP request. Use this instead of the sync variant
     * for high-concurrency scenarios.</p>
     *
     * @param agentId the agent's unique identifier
     * @return a CompletableFuture with the raw receipt bytes
     */
    public CompletableFuture<byte[]> getReceiptAsync(String agentId) {
        return service.getReceiptAsync(agentId);
    }

    /**
     * Retrieves the status token for an agent asynchronously.
     *
     * <p>This method uses non-blocking I/O and does not occupy a thread pool
     * thread during the HTTP request. Use this instead of the sync variant
     * for high-concurrency scenarios.</p>
     *
     * @param agentId the agent's unique identifier
     * @return a CompletableFuture with the raw status token bytes
     */
    public CompletableFuture<byte[]> getStatusTokenAsync(String agentId) {
        return service.getStatusTokenAsync(agentId);
    }

    /**
     * Retrieves the SCITT root public keys asynchronously.
     *
     * <p>This method uses non-blocking I/O and does not occupy a thread pool
     * thread during the HTTP request. The keys are cached with a configurable
     * TTL (default: 24 hours) to avoid redundant network calls.</p>
     *
     * <p>The returned map is keyed by hex key ID (4-byte SHA-256 of SPKI-DER),
     * enabling O(1) lookup by key ID from COSE headers.</p>
     *
     * @return a CompletableFuture with the root public keys (keyed by hex key ID)
     */
    public CompletableFuture<Map<String, PublicKey>> getRootKeysAsync() {
        return service.getRootKeysAsync();
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
        private Duration rootKeyCacheTtl = DEFAULT_ROOT_KEY_CACHE_TTL;

        private Builder() {
        }

        /**
         * Sets the base URL for the transparency log API.
         *
         * <p><b>Security note:</b> Only URLs pointing to trusted SCITT domains
         * (defined in {@link TrustedDomainRegistry}) are accepted. This prevents
         * root key substitution attacks where a malicious transparency log could
         * provide a forged root key.</p>
         *
         * @param baseUrl the base URL (default: https://transparency.ans.ote-godaddy.com)
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
         * Sets the cache TTL for the root public key.
         *
         * <p>The root key is cached to avoid redundant network calls during
         * verification. Since root keys rarely change, a long TTL is appropriate.</p>
         *
         * @param ttl the cache TTL (default: 24 hours)
         * @return this builder
         */
        public Builder rootKeyCacheTtl(Duration ttl) {
            this.rootKeyCacheTtl = ttl;
            return this;
        }

        /**
         * Builds the TransparencyClient.
         *
         * @return a new TransparencyClient instance
         * @throws SecurityException if the configured baseUrl is not a trusted SCITT domain
         */
        public TransparencyClient build() {
            validateTrustedDomain();
            return new TransparencyClient(baseUrl, connectTimeout, readTimeout, rootKeyCacheTtl);
        }

        private void validateTrustedDomain() {
            String host = URI.create(baseUrl).getHost();
            if (!TrustedDomainRegistry.isTrustedDomain(host)) {
                throw new SecurityException(
                    "Untrusted transparency log domain: " + host + ". "
                    + "Trusted domains: " + TrustedDomainRegistry.getTrustedDomains());
            }
        }
    }
}