package com.godaddy.ans.sdk.auth;

/**
 * Provider interface for obtaining ANS credentials.
 *
 * <p>This follows the credentials provider pattern similar to AWS SDK,
 * allowing for flexible credential sourcing strategies.</p>
 *
 * <p>Implementations include:</p>
 * <ul>
 *   <li>{@link JwtCredentialsProvider} - Static JWT token</li>
 *   <li>{@link ApiKeyCredentialsProvider} - API key and secret</li>
 *   <li>{@link EnvironmentCredentialsProvider} - From environment variables</li>
 *   <li>{@link RefreshableJwtCredentialsProvider} - Auto-refreshing JWT</li>
 * </ul>
 */
public interface AnsCredentialsProvider {

    /**
     * Resolves and returns the current credentials.
     *
     * <p>Implementations may cache credentials or fetch them on each call,
     * depending on the credential source.</p>
     *
     * @return the resolved credentials
     * @throws com.godaddy.ans.sdk.exception.AnsAuthenticationException if credentials cannot be resolved
     */
    AnsCredentials resolveCredentials();
}