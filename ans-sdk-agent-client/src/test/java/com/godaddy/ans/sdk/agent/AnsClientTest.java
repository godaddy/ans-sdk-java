package com.godaddy.ans.sdk.agent;

import com.godaddy.ans.sdk.agent.http.AgentHttpClientFactory;
import com.godaddy.ans.sdk.agent.verification.DaneTlsaVerifier;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Tests for AnsClient.
 */
class AnsClientTest {

    @Test
    void createReturnsClient() {
        AnsClient client = AnsClient.create();
        assertNotNull(client);
    }

    @Test
    void builderCreatesClient() {
        AnsClient client = AnsClient.builder().build();
        assertNotNull(client);
    }

    @Test
    void builderWithCustomFactory() {
        AgentHttpClientFactory mockFactory = mock(AgentHttpClientFactory.class);

        AnsClient client = AnsClient.builder()
            .httpClientFactory(mockFactory)
            .build();

        assertNotNull(client);
    }

    @Test
    void builderWithDaneVerifier() {
        DaneTlsaVerifier mockVerifier = mock(DaneTlsaVerifier.class);

        AnsClient client = AnsClient.builder()
            .daneVerifier(mockVerifier)
            .build();

        assertNotNull(client);
    }

    @Test
    void builderWithTimeouts() {
        AnsClient client = AnsClient.builder()
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(15))
            .build();

        assertNotNull(client);
    }

    @Test
    void builderMethodsReturnBuilder() {
        AnsClient.Builder builder = AnsClient.builder();
        AgentHttpClientFactory mockFactory = mock(AgentHttpClientFactory.class);
        DaneTlsaVerifier mockVerifier = mock(DaneTlsaVerifier.class);

        assertSame(builder, builder.httpClientFactory(mockFactory));
        assertSame(builder, builder.daneVerifier(mockVerifier));
        assertSame(builder, builder.connectTimeout(Duration.ofSeconds(5)));
        assertSame(builder, builder.readTimeout(Duration.ofSeconds(10)));
    }

    @Test
    void connectWithNullUrlThrows() {
        AnsClient client = AnsClient.create();

        assertThrows(NullPointerException.class, () ->
            client.connect(null));
    }

    @Test
    void connectWithNullOptionsThrows() {
        AnsClient client = AnsClient.create();

        assertThrows(NullPointerException.class, () ->
            client.connect("https://example.com", null));
    }

    @Test
    void builderWithFactoryAndDaneVerifier() {
        // When both factory and daneVerifier are set, factory takes precedence
        AgentHttpClientFactory mockFactory = mock(AgentHttpClientFactory.class);
        DaneTlsaVerifier mockVerifier = mock(DaneTlsaVerifier.class);

        AnsClient client = AnsClient.builder()
            .httpClientFactory(mockFactory)
            .daneVerifier(mockVerifier)
            .build();

        assertNotNull(client);
    }

    @Test
    void builderWithAllOptions() {
        AgentHttpClientFactory mockFactory = mock(AgentHttpClientFactory.class);

        AnsClient client = AnsClient.builder()
            .httpClientFactory(mockFactory)
            .connectTimeout(Duration.ofSeconds(20))
            .readTimeout(Duration.ofSeconds(60))
            .build();

        assertNotNull(client);
    }
}
