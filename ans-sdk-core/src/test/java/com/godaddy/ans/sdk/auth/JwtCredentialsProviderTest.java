package com.godaddy.ans.sdk.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for JwtCredentialsProvider.
 */
class JwtCredentialsProviderTest {

    @Test
    @DisplayName("Should return correct authorization header format")
    void shouldReturnCorrectAuthorizationHeader() {
        String token = "test-jwt-token";

        JwtCredentialsProvider provider = new JwtCredentialsProvider(token);
        AnsCredentials credentials = provider.resolveCredentials();

        assertThat(credentials.toAuthorizationHeader()).isEqualTo("sso-jwt test-jwt-token");
    }

    @Test
    @DisplayName("Should throw exception for null token")
    void shouldThrowExceptionForNullToken() {
        assertThatThrownBy(() -> new JwtCredentialsProvider(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for empty token")
    void shouldThrowExceptionForEmptyToken() {
        assertThatThrownBy(() -> new JwtCredentialsProvider(""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for blank token")
    void shouldThrowExceptionForBlankToken() {
        assertThatThrownBy(() -> new JwtCredentialsProvider("   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should return same credentials on multiple calls")
    void shouldReturnSameCredentialsOnMultipleCalls() {
        String token = "test-token";
        JwtCredentialsProvider provider = new JwtCredentialsProvider(token);

        AnsCredentials first = provider.resolveCredentials();
        AnsCredentials second = provider.resolveCredentials();

        assertThat(first).isSameAs(second);
    }
}