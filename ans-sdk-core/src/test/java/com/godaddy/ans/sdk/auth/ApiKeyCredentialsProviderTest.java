package com.godaddy.ans.sdk.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for ApiKeyCredentialsProvider.
 */
class ApiKeyCredentialsProviderTest {

    @Test
    @DisplayName("Should create provider with valid API key and secret")
    void shouldCreateProviderWithValidCredentials() {
        String apiKey = "my-api-key";
        String apiSecret = "my-api-secret";

        ApiKeyCredentialsProvider provider = new ApiKeyCredentialsProvider(apiKey, apiSecret);
        AnsCredentials credentials = provider.resolveCredentials();

        assertThat(credentials).isNotNull();
        assertThat(credentials.getType()).isEqualTo(AnsCredentials.CredentialType.API_KEY);
        assertThat(credentials.getApiKey()).isEqualTo(apiKey);
        assertThat(credentials.getApiSecret()).isEqualTo(apiSecret);
    }

    @Test
    @DisplayName("Should return correct authorization header format")
    void shouldReturnCorrectAuthorizationHeader() {
        String apiKey = "test-key";
        String apiSecret = "test-secret";

        ApiKeyCredentialsProvider provider = new ApiKeyCredentialsProvider(apiKey, apiSecret);
        AnsCredentials credentials = provider.resolveCredentials();

        assertThat(credentials.toAuthorizationHeader()).isEqualTo("sso-key test-key:test-secret");
    }

    @Test
    @DisplayName("Should throw exception for null API key")
    void shouldThrowExceptionForNullApiKey() {
        assertThatThrownBy(() -> new ApiKeyCredentialsProvider(null, "secret"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for null API secret")
    void shouldThrowExceptionForNullApiSecret() {
        assertThatThrownBy(() -> new ApiKeyCredentialsProvider("key", null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for empty API key")
    void shouldThrowExceptionForEmptyApiKey() {
        assertThatThrownBy(() -> new ApiKeyCredentialsProvider("", "secret"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for empty API secret")
    void shouldThrowExceptionForEmptyApiSecret() {
        assertThatThrownBy(() -> new ApiKeyCredentialsProvider("key", ""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should return same credentials on multiple calls")
    void shouldReturnSameCredentialsOnMultipleCalls() {
        ApiKeyCredentialsProvider provider = new ApiKeyCredentialsProvider("key", "secret");

        AnsCredentials first = provider.resolveCredentials();
        AnsCredentials second = provider.resolveCredentials();

        assertThat(first).isSameAs(second);
    }
}