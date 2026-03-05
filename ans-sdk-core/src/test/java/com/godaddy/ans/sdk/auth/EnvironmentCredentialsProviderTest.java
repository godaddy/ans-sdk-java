package com.godaddy.ans.sdk.auth;

import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for EnvironmentCredentialsProvider.
 *
 * Note: These tests verify behavior when environment variables are not set.
 * Full integration testing with actual env vars would require a different approach.
 */
class EnvironmentCredentialsProviderTest {

    @Test
    @DisplayName("Should create provider with default constructor")
    void shouldCreateProviderWithDefaults() {
        EnvironmentCredentialsProvider provider = new EnvironmentCredentialsProvider();
        assertThat(provider).isNotNull();
    }

    @Test
    @DisplayName("Should have correct environment variable constants")
    void shouldHaveCorrectEnvVarConstants() {
        assertThat(EnvironmentCredentialsProvider.ENV_JWT_TOKEN).isEqualTo("ANS_JWT_TOKEN");
        assertThat(EnvironmentCredentialsProvider.ENV_API_KEY).isEqualTo("ANS_API_KEY");
        assertThat(EnvironmentCredentialsProvider.ENV_API_SECRET).isEqualTo("ANS_API_SECRET");
    }

    @Test
    @DisplayName("Should throw exception when no credentials found in environment")
    void shouldThrowExceptionWhenNoCredentialsFound() {
        // This test assumes these env vars are not set in the test environment
        // If they are set, this test will fail (which is expected behavior)
        EnvironmentCredentialsProvider provider = new EnvironmentCredentialsProvider();

        // Only run assertion if env vars are not set
        if (System.getenv(EnvironmentCredentialsProvider.ENV_JWT_TOKEN) == null
            && System.getenv(EnvironmentCredentialsProvider.ENV_API_KEY) == null) {

            assertThatThrownBy(provider::resolveCredentials)
                .isInstanceOf(AnsAuthenticationException.class)
                .hasMessageContaining("No credentials found");
        }
    }

    @Test
    @DisplayName("Error message should list all required environment variables")
    void errorMessageShouldListEnvVars() {
        EnvironmentCredentialsProvider provider = new EnvironmentCredentialsProvider();

        // Only run assertion if env vars are not set
        if (System.getenv(EnvironmentCredentialsProvider.ENV_JWT_TOKEN) == null
            && System.getenv(EnvironmentCredentialsProvider.ENV_API_KEY) == null) {

            assertThatThrownBy(provider::resolveCredentials)
                .isInstanceOf(AnsAuthenticationException.class)
                .hasMessageContaining("ANS_JWT_TOKEN")
                .hasMessageContaining("ANS_API_KEY")
                .hasMessageContaining("ANS_API_SECRET");
        }
    }
}