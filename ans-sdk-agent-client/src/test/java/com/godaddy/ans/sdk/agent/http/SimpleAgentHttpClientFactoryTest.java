package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SimpleAgentHttpClientFactory}.
 */
class SimpleAgentHttpClientFactoryTest {

    private SimpleAgentHttpClientFactory factory;

    @BeforeEach
    void setUp() {
        factory = new SimpleAgentHttpClientFactory();
    }

    // ==================== create() Method Tests ====================

    @Test
    @DisplayName("create() should return valid HttpClient")
    void createShouldReturnValidHttpClient() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When
        HttpClient client = factory.create(hostname, options, timeout);

        // Then
        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("create() should respect connect timeout")
    void createShouldRespectConnectTimeout() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(30);

        // When
        HttpClient client = factory.create(hostname, options, timeout);

        // Then
        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).isPresent();
        assertThat(client.connectTimeout().get()).isEqualTo(timeout);
    }

    @Test
    @DisplayName("create() should work with different timeout values")
    void createShouldWorkWithDifferentTimeoutValues() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();

        // When/Then - short timeout
        Duration shortTimeout = Duration.ofMillis(500);
        HttpClient shortClient = factory.create(hostname, options, shortTimeout);
        assertThat(shortClient.connectTimeout()).contains(shortTimeout);

        // When/Then - long timeout
        Duration longTimeout = Duration.ofMinutes(2);
        HttpClient longClient = factory.create(hostname, options, longTimeout);
        assertThat(longClient.connectTimeout()).contains(longTimeout);
    }

    @Test
    @DisplayName("create() should ignore verification policy")
    void createShouldIgnoreVerificationPolicy() {
        // Given - various verification policies
        String hostname = "example.com";
        Duration timeout = Duration.ofSeconds(10);

        // When/Then - should work regardless of policy
        HttpClient pkiClient = factory.create(hostname,
            ConnectOptions.builder().verificationPolicy(VerificationPolicy.PKI_ONLY).build(),
            timeout);
        assertThat(pkiClient).isNotNull();

        HttpClient daneClient = factory.create(hostname,
            ConnectOptions.builder().verificationPolicy(VerificationPolicy.DANE_REQUIRED).build(),
            timeout);
        assertThat(daneClient).isNotNull();

        HttpClient badgeClient = factory.create(hostname,
            ConnectOptions.builder().verificationPolicy(VerificationPolicy.BADGE_REQUIRED).build(),
            timeout);
        assertThat(badgeClient).isNotNull();
    }

    // ==================== createVerified() Method Tests ====================

    @Test
    @DisplayName("createVerified() should return VerifiedClientResult")
    void createVerifiedShouldReturnVerifiedClientResult() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When
        VerifiedClientResult result = factory.createVerified(hostname, options, timeout);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.ansHttpClient()).isNotNull();
        assertThat(result.verifier()).isNotNull();
    }

    @Test
    @DisplayName("createVerified() should return NoOpConnectionVerifier")
    void createVerifiedShouldReturnNoOpConnectionVerifier() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When
        VerifiedClientResult result = factory.createVerified(hostname, options, timeout);

        // Then
        assertThat(result.verifier()).isEqualTo(NoOpConnectionVerifier.INSTANCE);
    }

    @Test
    @DisplayName("createVerified() ansHttpClient should have a valid delegate")
    void createVerifiedAnsHttpClientShouldHaveValidDelegate() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When
        VerifiedClientResult result = factory.createVerified(hostname, options, timeout);

        // Then - ansHttpClient should have a working delegate
        assertThat(result.ansHttpClient().getDelegate()).isNotNull();
    }

    @Test
    @DisplayName("createVerified() should configure connect timeout on delegate")
    void createVerifiedShouldConfigureTimeoutOnDelegate() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(15);

        // When
        VerifiedClientResult result = factory.createVerified(hostname, options, timeout);

        // Then
        HttpClient delegate = result.ansHttpClient().getDelegate();
        assertThat(delegate.connectTimeout()).contains(timeout);
    }

    @Test
    @DisplayName("createVerified() should work with various hostnames")
    void createVerifiedShouldWorkWithVariousHostnames() {
        // Given
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When/Then - standard hostname
        VerifiedClientResult result1 = factory.createVerified("example.com", options, timeout);
        assertThat(result1).isNotNull();

        // When/Then - hostname with subdomain
        VerifiedClientResult result2 = factory.createVerified("api.example.com", options, timeout);
        assertThat(result2).isNotNull();

        // When/Then - IP address
        VerifiedClientResult result3 = factory.createVerified("192.168.1.1", options, timeout);
        assertThat(result3).isNotNull();

        // When/Then - localhost
        VerifiedClientResult result4 = factory.createVerified("localhost", options, timeout);
        assertThat(result4).isNotNull();
    }

    // ==================== Edge Cases ====================

    @Test
    @DisplayName("Should create multiple independent clients")
    void shouldCreateMultipleIndependentClients() {
        // Given
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When
        HttpClient client1 = factory.create("host1.example.com", options, timeout);
        HttpClient client2 = factory.create("host2.example.com", options, timeout);

        // Then
        assertThat(client1).isNotNull();
        assertThat(client2).isNotNull();
        assertThat(client1).isNotSameAs(client2);
    }

    @Test
    @DisplayName("Should create multiple independent verified results")
    void shouldCreateMultipleIndependentVerifiedResults() {
        // Given
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When
        VerifiedClientResult result1 = factory.createVerified("host1.example.com", options, timeout);
        VerifiedClientResult result2 = factory.createVerified("host2.example.com", options, timeout);

        // Then
        assertThat(result1).isNotNull();
        assertThat(result2).isNotNull();
        assertThat(result1.ansHttpClient()).isNotSameAs(result2.ansHttpClient());
    }

    @Test
    @DisplayName("Factory should be reusable")
    void factoryShouldBeReusable() {
        // Given
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofSeconds(10);

        // When/Then - create multiple clients from same factory
        for (int i = 0; i < 5; i++) {
            HttpClient client = factory.create("host" + i + ".example.com", options, timeout);
            assertThat(client).isNotNull();
        }

        for (int i = 0; i < 5; i++) {
            VerifiedClientResult result = factory.createVerified("host" + i + ".example.com", options, timeout);
            assertThat(result).isNotNull();
        }
    }

    @Test
    @DisplayName("Very short timeout should be accepted")
    void veryShortTimeoutShouldBeAccepted() {
        // Given
        String hostname = "example.com";
        ConnectOptions options = ConnectOptions.defaults();
        Duration timeout = Duration.ofMillis(1);

        // When
        HttpClient client = factory.create(hostname, options, timeout);

        // Then
        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).contains(timeout);
    }
}
