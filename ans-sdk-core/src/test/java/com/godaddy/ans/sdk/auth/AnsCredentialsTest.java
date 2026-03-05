package com.godaddy.ans.sdk.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for AnsCredentials.
 */
class AnsCredentialsTest {

    @Test
    @DisplayName("Should create JWT credentials")
    void shouldCreateJwtCredentials() {
        AnsCredentials credentials = AnsCredentials.ofJwt("my-jwt-token");

        assertThat(credentials.getType()).isEqualTo(AnsCredentials.CredentialType.JWT);
        assertThat(credentials.getToken()).isEqualTo("my-jwt-token");
    }

    @Test
    @DisplayName("Should create API key credentials")
    void shouldCreateApiKeyCredentials() {
        AnsCredentials credentials = AnsCredentials.ofApiKey("my-key", "my-secret");

        assertThat(credentials.getType()).isEqualTo(AnsCredentials.CredentialType.API_KEY);
        assertThat(credentials.getApiKey()).isEqualTo("my-key");
        assertThat(credentials.getApiSecret()).isEqualTo("my-secret");
    }

    @Test
    @DisplayName("Should format JWT authorization header correctly")
    void shouldFormatJwtAuthorizationHeader() {
        AnsCredentials credentials = AnsCredentials.ofJwt("test-token");

        assertThat(credentials.toAuthorizationHeader()).isEqualTo("sso-jwt test-token");
    }

    @Test
    @DisplayName("Should format API key authorization header correctly")
    void shouldFormatApiKeyAuthorizationHeader() {
        AnsCredentials credentials = AnsCredentials.ofApiKey("key123", "secret456");

        assertThat(credentials.toAuthorizationHeader()).isEqualTo("sso-key key123:secret456");
    }

    @Test
    @DisplayName("JWT credentials should have null API key and secret")
    void jwtCredentialsShouldHaveNullApiFields() {
        AnsCredentials credentials = AnsCredentials.ofJwt("token");

        assertThat(credentials.getApiKey()).isNull();
        assertThat(credentials.getApiSecret()).isNull();
    }

    @Test
    @DisplayName("API key credentials should have null token")
    void apiKeyCredentialsShouldHaveNullToken() {
        AnsCredentials credentials = AnsCredentials.ofApiKey("key", "secret");

        assertThat(credentials.getToken()).isNull();
    }

    @Test
    @DisplayName("Should throw exception for null JWT token")
    void shouldThrowExceptionForNullJwtToken() {
        assertThatThrownBy(() -> AnsCredentials.ofJwt(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for blank JWT token")
    void shouldThrowExceptionForBlankJwtToken() {
        assertThatThrownBy(() -> AnsCredentials.ofJwt("   "))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for null API key")
    void shouldThrowExceptionForNullApiKey() {
        assertThatThrownBy(() -> AnsCredentials.ofApiKey(null, "secret"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Should throw exception for null API secret")
    void shouldThrowExceptionForNullApiSecret() {
        assertThatThrownBy(() -> AnsCredentials.ofApiKey("key", null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    @DisplayName("Credential type enum should have JWT and API_KEY")
    void credentialTypeEnumShouldHaveExpectedValues() {
        assertThat(AnsCredentials.CredentialType.values())
            .containsExactly(AnsCredentials.CredentialType.JWT, AnsCredentials.CredentialType.API_KEY);
    }
}
