package com.godaddy.ans.sdk.discovery;

import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;
import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.model.generated.AgentDetails;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * Client for ANS agent discovery and resolution operations.
 *
 * <p>This client provides methods for resolving agents by agentHost
 * and optional version constraints.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * DiscoveryClient client = DiscoveryClient.builder()
 *     .environment(Environment.OTE)
 *     .credentialsProvider(new JwtCredentialsProvider(jwtToken))
 *     .build();
 *
 * // Resolve latest version
 * AgentDetails agent = client.resolve("booking-agent.example.com", null);
 *
 * // Resolve with version constraint
 * AgentDetails agent = client.resolve("booking-agent.example.com", "^1.0.0");
 * }</pre>
 */
public final class DiscoveryClient {

    private final AnsConfiguration configuration;
    private final ResolutionService resolutionService;

    private DiscoveryClient(AnsConfiguration configuration) {
        this.configuration = configuration;
        this.resolutionService = new ResolutionService(configuration);
    }

    /**
     * Creates a new builder for constructing a DiscoveryClient.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    // ==================== Resolution Operations (Sync) ====================

    /**
     * Resolves an agent by agentHost.
     *
     * @param agentHost the agent's host (e.g., "booking-agent.example.com")
     * @param version optional version constraint (e.g., "^1.0.0", "~1.2.0", "1.2.3")
     * @return the resolved agent details
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if no matching agent is found
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     */
    public AgentDetails resolve(String agentHost, String version) {
        return resolutionService.resolve(agentHost, version);
    }

    /**
     * Resolves an agent by agentHost, returning the latest active version.
     *
     * @param agentHost the agent's host
     * @return the resolved agent details
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if no matching agent is found
     */
    public AgentDetails resolve(String agentHost) {
        return resolve(agentHost, null);
    }

    /**
     * Gets agent details by agent ID.
     *
     * <p>This method retrieves the full details of a registered agent using its unique ID.</p>
     *
     * @param agentId the agent's unique identifier (UUID)
     * @return the agent details
     * @throws com.godaddy.ans.sdk.exception.AnsNotFoundException if the agent is not found
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if authentication fails
     */
    public AgentDetails getAgent(String agentId) {
        return resolutionService.getAgent(agentId);
    }

    // ==================== Resolution Operations (Async) ====================

    /**
     * Resolves an agent asynchronously.
     *
     * @param agentHost the agent's host
     * @param version optional version constraint
     * @return a CompletableFuture with the resolved agent details
     */
    public CompletableFuture<AgentDetails> resolveAsync(String agentHost, String version) {
        return CompletableFuture.supplyAsync(() -> resolve(agentHost, version), AnsExecutors.sharedIoExecutor());
    }

    /**
     * Resolves an agent asynchronously, returning the latest active version.
     *
     * @param agentHost the agent's host
     * @return a CompletableFuture with the resolved agent details
     */
    public CompletableFuture<AgentDetails> resolveAsync(String agentHost) {
        return resolveAsync(agentHost, null);
    }

    /**
     * Gets agent details by agent ID asynchronously.
     *
     * @param agentId the agent's unique identifier (UUID)
     * @return a CompletableFuture with the agent details
     */
    public CompletableFuture<AgentDetails> getAgentAsync(String agentId) {
        return CompletableFuture.supplyAsync(() -> getAgent(agentId), AnsExecutors.sharedIoExecutor());
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
     * Builder for constructing a DiscoveryClient.
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
         * Builds the DiscoveryClient.
         *
         * @return a new DiscoveryClient instance
         */
        public DiscoveryClient build() {
            return new DiscoveryClient(configBuilder.build());
        }
    }
}