package com.godaddy.ans.sdk.config;

import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for ANS SDK clients.
 *
 * <p>This class holds all configuration options for ANS SDK clients,
 * including environment, credentials, timeouts, and retry settings.</p>
 *
 * <p>Use the builder to create instances:</p>
 * <pre>{@code
 * AnsConfiguration config = AnsConfiguration.builder()
 *     .environment(Environment.OTE)
 *     .credentialsProvider(new JwtCredentialsProvider(jwtToken))
 *     .connectTimeout(Duration.ofSeconds(10))
 *     .build();
 * }</pre>
 */
public final class AnsConfiguration {

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);
    private static final int DEFAULT_MAX_RETRIES = 3;

    private final Environment environment;
    private final String baseUrl;
    private final AnsCredentialsProvider credentialsProvider;
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final int maxRetries;

    private AnsConfiguration(Builder builder) {
        this.environment = builder.environment;
        this.baseUrl = builder.baseUrl != null ? builder.baseUrl : builder.environment.getBaseUrl();
        this.credentialsProvider = Objects.requireNonNull(builder.credentialsProvider,
            "Credentials provider is required");
        this.connectTimeout = builder.connectTimeout != null ? builder.connectTimeout : DEFAULT_CONNECT_TIMEOUT;
        this.readTimeout = builder.readTimeout != null ? builder.readTimeout : DEFAULT_READ_TIMEOUT;
        this.maxRetries = builder.maxRetries;
    }

    /**
     * Creates a new configuration builder.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the environment.
     *
     * @return the environment
     */
    public Environment getEnvironment() {
        return environment;
    }

    /**
     * Returns the base URL for API requests.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Returns the credentials provider.
     *
     * @return the credentials provider
     */
    public AnsCredentialsProvider getCredentialsProvider() {
        return credentialsProvider;
    }

    /**
     * Returns the connection timeout.
     *
     * @return the connection timeout
     */
    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * Returns the read timeout.
     *
     * @return the read timeout
     */
    public Duration getReadTimeout() {
        return readTimeout;
    }

    /**
     * Returns the maximum number of retry attempts.
     *
     * @return the maximum retry attempts
     */
    public int getMaxRetries() {
        return maxRetries;
    }

    /**
     * Returns whether retry is enabled.
     *
     * @return true if retry is enabled
     */
    public boolean isRetryEnabled() {
        return maxRetries > 0;
    }

    /**
     * Builder for {@link AnsConfiguration}.
     */
    public static final class Builder {

        private Environment environment = Environment.OTE;
        private String baseUrl;
        private AnsCredentialsProvider credentialsProvider;
        private Duration connectTimeout;
        private Duration readTimeout;
        private int maxRetries = DEFAULT_MAX_RETRIES;

        private Builder() {
        }

        /**
         * Sets the environment.
         *
         * @param environment the environment
         * @return this builder
         */
        public Builder environment(Environment environment) {
            this.environment = Objects.requireNonNull(environment, "Environment cannot be null");
            return this;
        }

        /**
         * Sets a custom base URL, overriding the environment's default URL.
         *
         * @param baseUrl the custom base URL
         * @return this builder
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * Sets the credentials provider.
         *
         * @param credentialsProvider the credentials provider
         * @return this builder
         */
        public Builder credentialsProvider(AnsCredentialsProvider credentialsProvider) {
            this.credentialsProvider = credentialsProvider;
            return this;
        }

        /**
         * Sets the connection timeout.
         *
         * @param connectTimeout the connection timeout
         * @return this builder
         */
        public Builder connectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
            return this;
        }

        /**
         * Sets the read timeout.
         *
         * @param readTimeout the read timeout
         * @return this builder
         */
        public Builder readTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
            return this;
        }

        /**
         * Enables retry with the specified maximum number of attempts.
         *
         * @param maxRetries the maximum number of retry attempts
         * @return this builder
         */
        public Builder enableRetry(int maxRetries) {
            if (maxRetries < 0) {
                throw new IllegalArgumentException("Max retries cannot be negative");
            }
            this.maxRetries = maxRetries;
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the configuration instance
         * @throws NullPointerException if required fields are not set
         */
        public AnsConfiguration build() {
            return new AnsConfiguration(this);
        }
    }
}