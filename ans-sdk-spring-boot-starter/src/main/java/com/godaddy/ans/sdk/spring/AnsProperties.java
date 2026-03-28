package com.godaddy.ans.sdk.spring;

import com.godaddy.ans.sdk.config.Environment;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for ANS SDK.
 *
 * <p>Properties are bound from the {@code ans} prefix in application properties.</p>
 *
 * <p>Example {@code application.yml}:</p>
 * <pre>
 * ans:
 *   environment: OTE
 *   credentials:
 *     type: api-key
 *     api-key: my-key
 *     api-secret: my-secret
 *   connect-timeout: 15s
 *   read-timeout: 45s
 *   max-retries: 5
 * </pre>
 */
@ConfigurationProperties(prefix = "ans")
public class AnsProperties {

    /**
     * ANS environment (OTE or PROD). Required.
     */
    private Environment environment;

    /**
     * Custom base URL. Overrides the environment's default URL when set.
     */
    private String baseUrl;

    /**
     * Connection timeout. Defaults to SDK default (10s) if not set.
     */
    private Duration connectTimeout;

    /**
     * Read timeout. Defaults to SDK default (30s) if not set.
     */
    private Duration readTimeout;

    /**
     * Maximum number of retry attempts. Defaults to SDK default (3) if not set.
     */
    private Integer maxRetries;

    /**
     * Whether auto-configuration is enabled. Defaults to true.
     */
    private boolean enabled = true;

    /**
     * Credential configuration.
     */
    private Credentials credentials = new Credentials();

    public Environment getEnvironment() {
        return environment;
    }

    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public Integer getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(Integer maxRetries) {
        this.maxRetries = maxRetries;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    public void setCredentials(Credentials credentials) {
        this.credentials = credentials;
    }

    /**
     * Credential configuration properties.
     */
    public static class Credentials {

        /**
         * Credential type: jwt, api-key, or environment.
         */
        private CredentialType type;

        /**
         * JWT token. Used when type is jwt.
         */
        private String jwtToken;

        /**
         * API key. Used when type is api-key.
         */
        private String apiKey;

        /**
         * API secret. Used when type is api-key.
         */
        private String apiSecret;

        public CredentialType getType() {
            return type;
        }

        public void setType(CredentialType type) {
            this.type = type;
        }

        public String getJwtToken() {
            return jwtToken;
        }

        public void setJwtToken(String jwtToken) {
            this.jwtToken = jwtToken;
        }

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getApiSecret() {
            return apiSecret;
        }

        public void setApiSecret(String apiSecret) {
            this.apiSecret = apiSecret;
        }
    }

    /**
     * Supported credential types.
     */
    public enum CredentialType {
        /** JWT bearer token. */
        JWT,
        /** API key + secret pair. */
        API_KEY,
        /** Read credentials from environment variables (ANS_JWT_TOKEN or ANS_API_KEY + ANS_API_SECRET). */
        ENVIRONMENT
    }
}
