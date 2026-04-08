package com.godaddy.ans.sdk.config;

import com.godaddy.ans.sdk.auth.AnsCredentialsProvider;
import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for AnsConfiguration.
 */
class AnsConfigurationTest {

    private final AnsCredentialsProvider testProvider = new JwtCredentialsProvider("test-token");

    @Test
    @DisplayName("Should create configuration with OTE environment")
    void shouldCreateConfigWithOteEnvironment() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("https://api.ote-godaddy.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.OTE);
    }

    @Test
    @DisplayName("Should create configuration with PROD environment")
    void shouldCreateConfigWithProdEnvironment() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.PROD)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("https://api.godaddy.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.PROD);
    }

    @Test
    @DisplayName("Should override base URL when explicitly set")
    void shouldOverrideBaseUrl() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .baseUrl("http://localhost:8080")
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("http://localhost:8080");
    }

    @Test
    @DisplayName("Should use default timeouts")
    void shouldUseDefaultTimeouts() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    @DisplayName("Should set custom timeouts")
    void shouldSetCustomTimeouts() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .credentialsProvider(testProvider)
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(60))
            .build();

        assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    @DisplayName("Should configure retry settings")
    void shouldConfigureRetrySettings() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .credentialsProvider(testProvider)
            .enableRetry(5)
            .build();

        assertThat(config.isRetryEnabled()).isTrue();
        assertThat(config.getMaxRetries()).isEqualTo(5);
    }

    @Test
    @DisplayName("Should enable retry by default with 3 retries")
    void shouldEnableRetryByDefault() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.isRetryEnabled()).isTrue();
        assertThat(config.getMaxRetries()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should throw exception when credentials provider is null")
    void shouldThrowExceptionWhenCredentialsProviderIsNull() {
        assertThatThrownBy(() -> AnsConfiguration.builder()
            .environment(Environment.OTE)
            .build())
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Credentials provider");
    }

    @Test
    @DisplayName("Should throw when environment is not set")
    void shouldThrowWhenEnvironmentNotSet() {
        assertThatThrownBy(() -> AnsConfiguration.builder()
            .credentialsProvider(testProvider)
            .build())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Environment is required");
    }

    @Test
    @DisplayName("Should allow custom base URL with explicit environment")
    void shouldAllowCustomBaseUrlWithExplicitEnvironment() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .baseUrl("http://custom-url.com")
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("http://custom-url.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.OTE);
    }

    @Test
    @DisplayName("Should return credentials provider")
    void shouldReturnCredentialsProvider() {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getCredentialsProvider()).isSameAs(testProvider);
    }
}