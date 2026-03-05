package com.godaddy.ans.sdk.auth;

/**
 * Represents credentials for authenticating with the ANS API.
 */
public final class AnsCredentials {

    private final CredentialType type;
    private final String token;
    private final String apiKey;
    private final String apiSecret;

    private AnsCredentials(CredentialType type, String token, String apiKey, String apiSecret) {
        this.type = type;
        this.token = token;
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
    }

    /**
     * Creates JWT token credentials.
     *
     * @param token the JWT token
     * @return credentials instance
     */
    public static AnsCredentials ofJwt(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("JWT token cannot be null or blank");
        }
        return new AnsCredentials(CredentialType.JWT, token, null, null);
    }

    /**
     * Creates API key credentials.
     *
     * @param apiKey the API key
     * @param apiSecret the API secret
     * @return credentials instance
     */
    public static AnsCredentials ofApiKey(String apiKey, String apiSecret) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("API key cannot be null or blank");
        }
        if (apiSecret == null || apiSecret.isBlank()) {
            throw new IllegalArgumentException("API secret cannot be null or blank");
        }
        return new AnsCredentials(CredentialType.API_KEY, null, apiKey, apiSecret);
    }

    /**
     * Returns the credential type.
     *
     * @return the credential type
     */
    public CredentialType getType() {
        return type;
    }

    /**
     * Returns the JWT token (only for JWT credentials).
     *
     * @return the JWT token, or null if not JWT credentials
     */
    public String getToken() {
        return token;
    }

    /**
     * Returns the API key (only for API key credentials).
     *
     * @return the API key, or null if not API key credentials
     */
    public String getApiKey() {
        return apiKey;
    }

    /**
     * Returns the API secret (only for API key credentials).
     *
     * @return the API secret, or null if not API key credentials
     */
    public String getApiSecret() {
        return apiSecret;
    }

    /**
     * Returns the Authorization header value for these credentials.
     *
     * @return the authorization header value
     */
    public String toAuthorizationHeader() {
        return switch (type) {
            case JWT -> "sso-jwt " + token;
            case API_KEY -> "sso-key " + apiKey + ":" + apiSecret;
        };
    }

    /**
     * The type of credentials.
     */
    public enum CredentialType {
        JWT,
        API_KEY
    }
}