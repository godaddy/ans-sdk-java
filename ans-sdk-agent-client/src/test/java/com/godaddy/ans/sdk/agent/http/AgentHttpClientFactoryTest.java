package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.AnsClient;
import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.connection.AgentConnection;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AgentHttpClientFactory} and its integration with {@link AnsClient}.
 */
@ExtendWith(MockitoExtension.class)
class AgentHttpClientFactoryTest {

    @Mock
    private AgentHttpClientFactory mockFactory;

    @Mock
    private HttpClient mockHttpClient;

    @Mock
    private AnsHttpClient mockAnsHttpClient;

    @Mock
    private ConnectionVerifier mockVerifier;

    @Test
    void createDefaultShouldReturnDefaultFactory() {
        // When
        AgentHttpClientFactory factory = AgentHttpClientFactory.createDefault();

        // Then
        assertThat(factory).isInstanceOf(DefaultAgentHttpClientFactory.class);
    }

    @Test
    void simpleShouldReturnSimpleFactory() {
        // When
        AgentHttpClientFactory factory = AgentHttpClientFactory.simple();

        // Then
        assertThat(factory).isInstanceOf(SimpleAgentHttpClientFactory.class);
    }

    @Test
    void simpleFactoryShouldCreateBasicHttpClient() {
        // Given
        AgentHttpClientFactory factory = AgentHttpClientFactory.simple();
        ConnectOptions options = ConnectOptions.defaults();

        // When
        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        // Then
        assertThat(client).isNotNull();
    }

    @Test
    void ansClientShouldUseMockFactory() {
        // Given
        VerifiedClientResult result = new VerifiedClientResult(mockVerifier, mockAnsHttpClient);
        when(mockFactory.createVerified(eq("agent.example.com"), any(ConnectOptions.class), any(Duration.class)))
            .thenReturn(result);
        when(mockAnsHttpClient.getDelegate()).thenReturn(mockHttpClient);

        AnsClient client = AnsClient.builder()
            .httpClientFactory(mockFactory)
            .build();

        // When
        AgentConnection connection = client.connect("https://agent.example.com");

        // Then
        verify(mockFactory).createVerified(eq("agent.example.com"), any(ConnectOptions.class), any(Duration.class));
        assertThat(connection).isNotNull();
        assertThat(connection.getHttpClient()).isSameAs(mockHttpClient);
    }

    @Test
    void ansClientShouldPassConnectOptionsToFactory() {
        // Given
        VerifiedClientResult result = new VerifiedClientResult(mockVerifier, mockAnsHttpClient);
        when(mockFactory.createVerified(any(), any(), any())).thenReturn(result);

        AnsClient client = AnsClient.builder()
            .httpClientFactory(mockFactory)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
            .build();

        // When
        client.connect("https://agent.example.com", options);

        // Then
        verify(mockFactory).createVerified(
            eq("agent.example.com"),
            eq(options),
            eq(Duration.ofSeconds(5))
        );
    }

    @Test
    void ansClientWithSimpleFactoryShouldWorkForTesting() {
        // Given - Use simple factory for testing without SSL complexity
        AnsClient client = AnsClient.builder()
            .httpClientFactory(AgentHttpClientFactory.simple())
            .build();

        // When
        AgentConnection connection = client.connect("https://example.com");

        // Then
        assertThat(connection).isNotNull();
        assertThat(connection.getAgentHost()).isEqualTo("example.com");
    }
}
