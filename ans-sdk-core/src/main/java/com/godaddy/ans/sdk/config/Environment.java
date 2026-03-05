package com.godaddy.ans.sdk.config;

/**
 * Enumeration of available ANS environments.
 *
 * <p>Each environment corresponds to a different deployment of the ANS Registry
 * accessible via the public API gateway.</p>
 *
 * <p>For external domain registration, use {@link #OTE} for testing and
 * {@link #PROD} for production workloads.</p>
 */
public enum Environment {

    /**
     * OTE (Operational Test Environment) for pre-production testing.
     *
     * <p>Use this environment to test your integration before going to production.</p>
     */
    OTE("https://api.ote-godaddy.com"),

    /**
     * Production environment.
     *
     * <p>Use this environment for production workloads.</p>
     */
    PROD("https://api.godaddy.com");

    private final String baseUrl;

    Environment(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Returns the base URL for this environment.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Returns the environment for the specified base URL.
     *
     * @param baseUrl the base URL to match
     * @return the matching environment
     * @throws IllegalArgumentException if no environment matches the URL
     */
    public static Environment fromBaseUrl(String baseUrl) {
        for (Environment env : values()) {
            if (env.baseUrl.equals(baseUrl)) {
                return env;
            }
        }
        throw new IllegalArgumentException("Unknown environment for URL: " + baseUrl);
    }
}