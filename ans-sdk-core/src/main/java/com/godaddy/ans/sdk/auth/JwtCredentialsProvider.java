package com.godaddy.ans.sdk.auth;

/**
 * Credentials provider that uses a static JWT token.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * AnsCredentialsProvider provider = new JwtCredentialsProvider(jwtToken);
 * }</pre>
 */
public final class JwtCredentialsProvider implements AnsCredentialsProvider {

    private final AnsCredentials credentials;

    /**
     * Creates a provider with the specified JWT token.
     *
     * @param jwtToken the JWT token
     * @throws IllegalArgumentException if the token is null or blank
     */
    public JwtCredentialsProvider(String jwtToken) {
        this.credentials = AnsCredentials.ofJwt(jwtToken);
    }

    @Override
    public AnsCredentials resolveCredentials() {
        return credentials;
    }
}