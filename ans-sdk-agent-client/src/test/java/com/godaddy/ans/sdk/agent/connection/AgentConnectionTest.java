package com.godaddy.ans.sdk.agent.connection;

import com.godaddy.ans.sdk.agent.http.AnsHttpClient;
import com.godaddy.ans.sdk.agent.protocol.HttpApiClient;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentEndpoint;
import com.godaddy.ans.sdk.model.generated.AgentLifecycleStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentConnectionTest {

    @Mock
    private AnsHttpClient ansHttpClient;

    @Mock
    private HttpClient httpClient;

    private AgentDetails agentDetails;

    @BeforeEach
    void setUp() {
        // Create test agent details with endpoints
        AgentEndpoint httpApiEndpoint = new AgentEndpoint();
        httpApiEndpoint.setProtocol(AgentEndpoint.ProtocolEnum.HTTP_API);
        httpApiEndpoint.setAgentUrl(URI.create("https://agent.example.com/api"));
        httpApiEndpoint.setMetaDataUrl(URI.create("https://agent.example.com/metadata"));

        AgentEndpoint a2aEndpoint = new AgentEndpoint();
        a2aEndpoint.setProtocol(AgentEndpoint.ProtocolEnum.A2_A);
        a2aEndpoint.setAgentUrl(URI.create("wss://agent.example.com/a2a"));

        agentDetails = new AgentDetails();
        agentDetails.setAgentId("test-agent-id");
        agentDetails.setAnsName("ans://v1.0.0.agent.example.com");
        agentDetails.setAgentHost("agent.example.com");
        agentDetails.setVersion("1.0.0");
        agentDetails.setAgentStatus(AgentLifecycleStatus.ACTIVE);
        agentDetails.setEndpoints(List.of(httpApiEndpoint, a2aEndpoint));
    }

    @Test
    void constructorWithValidParametersShouldSucceed() {
        // Given/When
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // Then
        assertThat(connection.getAgentDetails()).isEqualTo(agentDetails);
        assertThat(connection.getAnsName()).isEqualTo("ans://v1.0.0.agent.example.com");
        assertThat(connection.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(connection.getVersion()).isEqualTo("1.0.0");
    }

    @Test
    void constructorWithNullAgentDetailsShouldThrowException() {
        assertThatThrownBy(() -> new AgentConnection(null, ansHttpClient))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Agent details");
    }

    @Test
    void constructorWithNullHttpClientShouldThrowException() {
        assertThatThrownBy(() -> new AgentConnection(agentDetails, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("client");
    }

    @Test
    void supportsProtocolWithSupportedProtocolShouldReturnTrue() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When/Then - using enum name format
        assertThat(connection.supportsProtocol("HTTP_API")).isTrue();
        assertThat(connection.supportsProtocol("A2A")).isTrue();
    }

    @Test
    void supportsProtocolWithProtocolValueShouldReturnTrue() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When/Then - using protocol value format (HTTP-API)
        assertThat(connection.supportsProtocol("HTTP-API")).isTrue();
    }

    @Test
    void supportsProtocolWithUnsupportedProtocolShouldReturnFalse() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When/Then
        assertThat(connection.supportsProtocol("MCP")).isFalse();
        assertThat(connection.supportsProtocol("UNKNOWN")).isFalse();
    }

    @Test
    void getEndpointUrlWithSupportedProtocolShouldReturnUrl() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When
        Optional<String> url = connection.getEndpointUrl("HTTP_API");

        // Then
        assertThat(url).isPresent();
        assertThat(url.get()).isEqualTo("https://agent.example.com/api");
    }

    @Test
    void getEndpointUrlWithUnsupportedProtocolShouldReturnEmpty() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When
        Optional<String> url = connection.getEndpointUrl("MCP");

        // Then
        assertThat(url).isEmpty();
    }

    @Test
    void getMetadataUrlWithAvailableMetadataShouldReturnUrl() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When
        Optional<String> url = connection.getMetadataUrl("HTTP_API");

        // Then
        assertThat(url).isPresent();
        assertThat(url.get()).isEqualTo("https://agent.example.com/metadata");
    }

    @Test
    void httpApiAtWithCustomUrlShouldReturnNewClient() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When
        HttpApiClient client = connection.httpApiAt("https://custom.example.com/api");

        // Then
        assertThat(client).isNotNull();
        assertThat(client.getBaseUrl()).isEqualTo("https://custom.example.com/api");
    }

    @Test
    void getHttpClientShouldReturnUnderlyingClient() {
        // Given
        when(ansHttpClient.getDelegate()).thenReturn(httpClient);
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When/Then
        assertThat(connection.getHttpClient()).isSameAs(httpClient);
    }

    @Test
    void getAnsHttpClientShouldReturnClient() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When/Then
        assertThat(connection.getAnsHttpClient()).isSameAs(ansHttpClient);
    }

    @Test
    void toStringShouldIncludeRelevantInfo() {
        // Given
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient);

        // When
        String str = connection.toString();

        // Then
        assertThat(str).contains("ansName");
        assertThat(str).contains("agentHost");
        assertThat(str).contains("version");
    }

    @Test
    void constructorWithCustomTimeoutShouldUseThatTimeout() {
        // Given
        Duration customTimeout = Duration.ofMinutes(5);

        // When
        AgentConnection connection = new AgentConnection(agentDetails, ansHttpClient, customTimeout);

        // Then
        HttpApiClient httpApiClient = connection.httpApiAt("https://example.com");
        assertThat(httpApiClient.getTimeout()).isEqualTo(customTimeout);
    }
}
