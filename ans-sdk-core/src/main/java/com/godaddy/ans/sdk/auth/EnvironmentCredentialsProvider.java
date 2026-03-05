package com.godaddy.ans.sdk.auth;

import com.godaddy.ans.sdk.exception.AnsAuthenticationException;

/**
 * Credentials provider that resolves credentials from environment variables.
 *
 * <p>This provider checks for the following environment variables in order:</p>
 * <ol>
 *   <li>{@code ANS_JWT_TOKEN} - JWT token for SSO authentication</li>
 *   <li>{@code ANS_API_KEY} and {@code ANS_API_SECRET} - API key authentication</li>
 * </ol>
 *
 * <p>If {@code ANS_JWT_TOKEN} is set, it takes precedence over API key authentication.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * // Set environment variables:
 * // export ANS_JWT_TOKEN="your-jwt-token"
 * // or
 * // export ANS_API_KEY="your-api-key"
 * // export ANS_API_SECRET="your-api-secret"
 *
 * AnsCredentialsProvider provider = new EnvironmentCredentialsProvider();
 * }</pre>
 */
public final class EnvironmentCredentialsProvider implements AnsCredentialsProvider {

    /** Environment variable name for JWT token. */
    public static final String ENV_JWT_TOKEN = "ANS_JWT_TOKEN";

    /** Environment variable name for API key. */
    public static final String ENV_API_KEY = "ANS_API_KEY";

    /** Environment variable name for API secret. */
    public static final String ENV_API_SECRET = "ANS_API_SECRET";

    @Override
    public AnsCredentials resolveCredentials() {
        // First, check for JWT token
        String jwtToken = System.getenv(ENV_JWT_TOKEN);
        if (jwtToken != null && !jwtToken.isBlank()) {
            return AnsCredentials.ofJwt(jwtToken);
        }

        // Then, check for API key and secret
        String apiKey = System.getenv(ENV_API_KEY);
        String apiSecret = System.getenv(ENV_API_SECRET);

        if (apiKey != null && !apiKey.isBlank() && apiSecret != null && !apiSecret.isBlank()) {
            return AnsCredentials.ofApiKey(apiKey, apiSecret);
        }

        // No credentials found
        throw new AnsAuthenticationException(
            "No credentials found. Set either " + ENV_JWT_TOKEN
            + " or both " + ENV_API_KEY + " and " + ENV_API_SECRET + " environment variables."
        );
    }
}