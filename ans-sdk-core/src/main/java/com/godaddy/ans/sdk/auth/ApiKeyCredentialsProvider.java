package com.godaddy.ans.sdk.auth;

/**
 * Credentials provider that uses an API key and secret.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * AnsCredentialsProvider provider = new ApiKeyCredentialsProvider(apiKey, apiSecret);
 * }</pre>
 */
public final class ApiKeyCredentialsProvider implements AnsCredentialsProvider {

    private final AnsCredentials credentials;

    /**
     * Creates a provider with the specified API key and secret.
     *
     * @param apiKey the API key
     * @param apiSecret the API secret
     * @throws IllegalArgumentException if either parameter is null or blank
     */
    public ApiKeyCredentialsProvider(String apiKey, String apiSecret) {
        this.credentials = AnsCredentials.ofApiKey(apiKey, apiSecret);
    }

    @Override
    public AnsCredentials resolveCredentials() {
        return credentials;
    }
}