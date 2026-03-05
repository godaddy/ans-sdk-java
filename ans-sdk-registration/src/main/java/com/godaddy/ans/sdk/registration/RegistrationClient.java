package com.godaddy.ans.sdk.registration;

import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;
import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentRegistrationRequest;
import com.godaddy.ans.sdk.model.generated.AgentRevocationRequest;
import com.godaddy.ans.sdk.model.generated.AgentRevocationResponse;
import com.godaddy.ans.sdk.model.generated.AgentStatus;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * Client for ANS agent registration operations.
 *
 * <p>This client provides methods for registering agents, verifying ACME challenges,
 * verifying DNS records, revoking registrations, and managing agent certificates.</p>
 *
 * <p>Example registration flow:</p>
 * <pre>{@code
 * RegistrationClient client = RegistrationClient.builder()
 *     .environment(Environment.OTE)
 *     .credentialsProvider(new JwtCredentialsProvider(jwtToken))
 *     .build();
 *
 * AgentDetails agent = client.registerAgent(request);
 * // AgentDetails contains agentId and registrationPending with challenges/nextSteps
 * AgentStatus acmeStatus = client.verifyAcme(agent.getAgentId());
 * AgentStatus dnsStatus = client.verifyDns(agent.getAgentId());
 * }</pre>
 *
 * <p>Example revocation:</p>
 * <pre>{@code
 * // Revoke with just reason
 * AgentRevocationResponse response = client.revokeAgent(agentId, RevocationReason.CESSATION_OF_OPERATION);
 *
 * // Revoke with reason and comments
 * AgentRevocationRequest request = new AgentRevocationRequest()
 *     .reason(RevocationReason.KEY_COMPROMISE)
 *     .comments("Private key may have been exposed");
 * AgentRevocationResponse response = client.revokeAgent(agentId, request);
 *
 * // DNS records to clean up after revocation
 * response.getDnsRecordsToRemove().forEach(record ->
 *     System.out.println("Remove: " + record.getName() + " " + record.getType()));
 * }</pre>
 */
public final class RegistrationClient {

    private final AnsConfiguration configuration;
    private final RegistrationService registrationService;
    private final CertificateService certificateService;

    private RegistrationClient(AnsConfiguration configuration) {
        this.configuration = configuration;
        this.registrationService = new RegistrationService(configuration);
        this.certificateService = new CertificateService(configuration);
    }

    /**
     * Creates a new builder for constructing a RegistrationClient.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    // ==================== Registration Operations (Sync) ====================

    /**
     * Registers a new agent with the ANS Registry.
     *
     * <p>This method registers the agent and automatically fetches the full agent details
     * including the agentId, which is needed for subsequent operations like verifyAcme.</p>
     *
     * @param request the registration request
     * @return the agent details including agentId and registration pending info
     * @throws com.godaddy.ans.sdk.exception.AnsValidationException if the request is invalid
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     * @throws com.godaddy.ans.sdk.exception.AnsServerException if a server error occurs
     */
    public AgentDetails registerAgent(AgentRegistrationRequest request) {
        return registrationService.register(request);
    }

    /**
     * Triggers ACME domain validation for the specified agent.
     *
     * <p>This should be called after the DNS TXT record has been configured
     * with the ACME challenge value.</p>
     *
     * @param agentId the agent ID
     * @return the updated agent status
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     */
    public AgentStatus verifyAcme(String agentId) {
        return registrationService.verifyAcme(agentId);
    }

    /**
     * Verifies DNS records for the specified agent.
     *
     * <p>This should be called after ACME verification succeeds and the
     * agent's DNS records have been configured.</p>
     *
     * @param agentId the agent ID
     * @return the updated agent status
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     */
    public AgentStatus verifyDns(String agentId) {
        return registrationService.verifyDns(agentId);
    }

    /**
     * Retrieves agent details by agent ID.
     *
     * <p>Use this to get the current state of an agent, including any pending
     * registration information such as DNS records to configure.</p>
     *
     * @param agentId the agent ID
     * @return the agent details
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     */
    public AgentDetails getAgent(String agentId) {
        return registrationService.getAgent(agentId);
    }

    /**
     * Revokes an agent registration.
     *
     * <p>For ACTIVE agents, this revokes the agent's certificates and marks the
     * registration as REVOKED in the transparency log. For PENDING registrations
     * (after ACME verification), this cancels the registration and revokes any
     * already-issued certificates.</p>
     *
     * <p>The response includes DNS records that should be removed from the agent's
     * domain (e.g., _ra-badge, _ans, TLSA records).</p>
     *
     * @param agentId the agent ID to revoke
     * @param request the revocation request with reason and optional comments
     * @return the revocation response with details about DNS records to remove
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     * @throws com.godaddy.ans.sdk.exception.AnsValidationException if the agent cannot be revoked
     *         (e.g., already revoked, in PENDING_VALIDATION state)
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     */
    public AgentRevocationResponse revokeAgent(String agentId, AgentRevocationRequest request) {
        return registrationService.revoke(agentId, request);
    }

    /**
     * Revokes an agent registration with just a reason code.
     *
     * <p>Convenience method that creates a revocation request with the specified reason.</p>
     *
     * @param agentId the agent ID to revoke
     * @param reason the reason for revocation
     * @return the revocation response
     * @see #revokeAgent(String, AgentRevocationRequest)
     */
    public AgentRevocationResponse revokeAgent(String agentId, AgentRevocationRequest.ReasonEnum reason) {
        AgentRevocationRequest request = new AgentRevocationRequest().reason(reason);
        return revokeAgent(agentId, request);
    }

    // ==================== Registration Operations (Async) ====================

    /**
     * Registers a new agent asynchronously.
     *
     * @param request the registration request
     * @return a CompletableFuture with the agent details
     */
    public CompletableFuture<AgentDetails> registerAgentAsync(AgentRegistrationRequest request) {
        return CompletableFuture.supplyAsync(() -> registerAgent(request), AnsExecutors.sharedIoExecutor());
    }

    /**
     * Triggers ACME domain validation asynchronously.
     *
     * @param agentId the agent ID
     * @return a CompletableFuture with the updated agent status
     */
    public CompletableFuture<AgentStatus> verifyAcmeAsync(String agentId) {
        return CompletableFuture.supplyAsync(() -> verifyAcme(agentId), AnsExecutors.sharedIoExecutor());
    }

    /**
     * Verifies DNS records asynchronously.
     *
     * @param agentId the agent ID
     * @return a CompletableFuture with the updated agent status
     */
    public CompletableFuture<AgentStatus> verifyDnsAsync(String agentId) {
        return CompletableFuture.supplyAsync(() -> verifyDns(agentId), AnsExecutors.sharedIoExecutor());
    }

    /**
     * Revokes an agent registration asynchronously.
     *
     * @param agentId the agent ID to revoke
     * @param request the revocation request
     * @return a CompletableFuture with the revocation response
     */
    public CompletableFuture<AgentRevocationResponse> revokeAgentAsync(String agentId, AgentRevocationRequest request) {
        return CompletableFuture.supplyAsync(() -> revokeAgent(agentId, request), AnsExecutors.sharedIoExecutor());
    }

    /**
     * Revokes an agent registration asynchronously with just a reason code.
     *
     * @param agentId the agent ID to revoke
     * @param reason the reason for revocation
     * @return a CompletableFuture with the revocation response
     */
    public CompletableFuture<AgentRevocationResponse> revokeAgentAsync(String agentId,
                                                                       AgentRevocationRequest.ReasonEnum reason) {
        return CompletableFuture.supplyAsync(() -> revokeAgent(agentId, reason), AnsExecutors.sharedIoExecutor());
    }

    // ==================== Certificate Operations ====================

    /**
     * Returns the certificate service for managing agent certificates.
     *
     * @return the certificate service
     */
    public CertificateService certificates() {
        return certificateService;
    }

    /**
     * Returns the current configuration.
     *
     * @return the configuration
     */
    public AnsConfiguration getConfiguration() {
        return configuration;
    }

    /**
     * Builder for constructing a RegistrationClient.
     */
    public static final class Builder {

        private final AnsConfiguration.Builder configBuilder = AnsConfiguration.builder();

        private Builder() {
        }

        /**
         * Sets the environment.
         *
         * @param environment the environment
         * @return this builder
         */
        public Builder environment(Environment environment) {
            configBuilder.environment(environment);
            return this;
        }

        /**
         * Sets a custom base URL.
         *
         * @param baseUrl the base URL
         * @return this builder
         */
        public Builder baseUrl(String baseUrl) {
            configBuilder.baseUrl(baseUrl);
            return this;
        }

        /**
         * Sets the credentials provider.
         *
         * @param credentialsProvider the credentials provider
         * @return this builder
         */
        public Builder credentialsProvider(AnsCredentialsProvider credentialsProvider) {
            configBuilder.credentialsProvider(credentialsProvider);
            return this;
        }

        /**
         * Sets the connection timeout.
         *
         * @param timeout the connection timeout
         * @return this builder
         */
        public Builder connectTimeout(Duration timeout) {
            configBuilder.connectTimeout(timeout);
            return this;
        }

        /**
         * Sets the read timeout.
         *
         * @param timeout the read timeout
         * @return this builder
         */
        public Builder readTimeout(Duration timeout) {
            configBuilder.readTimeout(timeout);
            return this;
        }

        /**
         * Enables retry with the specified maximum number of attempts.
         *
         * @param maxRetries the maximum number of retry attempts
         * @return this builder
         */
        public Builder enableRetry(int maxRetries) {
            configBuilder.enableRetry(maxRetries);
            return this;
        }

        /**
         * Builds the RegistrationClient.
         *
         * @return a new RegistrationClient instance
         */
        public RegistrationClient build() {
            return new RegistrationClient(configBuilder.build());
        }
    }
}