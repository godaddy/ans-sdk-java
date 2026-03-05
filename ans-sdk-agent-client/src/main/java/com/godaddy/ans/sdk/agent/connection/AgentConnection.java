package com.godaddy.ans.sdk.agent.connection;

import com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider;
import com.godaddy.ans.sdk.agent.http.AnsHttpClient;
import com.godaddy.ans.sdk.agent.protocol.HttpApiClient;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentEndpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Represents an active connection to a remote ANS agent.
 *
 * <p>An AgentConnection encapsulates all the information needed to communicate
 * with a remote agent, including the resolved agent details and the configured
 * HTTP client for making requests.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * AnsClient client = AnsClient.create();
 * AgentConnection conn = client.connect("https://agent.example.com:8443");
 *
 * // Use HTTP-API client
 * HttpApiClient httpApi = conn.httpApiAt("https://agent.example.com:8443");
 * MyResponse response = httpApi.get("/api/v1/resource", MyResponse.class);
 *
 * // Get agent details
 * AgentDetails details = conn.getAgentDetails();
 * System.out.println("Connected to: " + details.getAgentHost());
 * }</pre>
 */
public final class AgentConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(AgentConnection.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final AgentDetails agentDetails;
    private final AnsHttpClient ansHttpClient;
    private final Duration timeout;
    private final HttpAuthHeadersProvider httpAuthHeadersProvider;

    /**
     * Creates a new AgentConnection.
     *
     * @param agentDetails the resolved agent details
     * @param ansHttpClient the verifying HTTP client
     */
    public AgentConnection(AgentDetails agentDetails, AnsHttpClient ansHttpClient) {
        this(agentDetails, ansHttpClient, DEFAULT_TIMEOUT, null);
    }

    /**
     * Creates a new AgentConnection with custom timeout.
     *
     * @param agentDetails the resolved agent details
     * @param ansHttpClient the verifying HTTP client
     * @param timeout the default timeout for requests
     */
    public AgentConnection(AgentDetails agentDetails, AnsHttpClient ansHttpClient, Duration timeout) {
        this(agentDetails, ansHttpClient, timeout, null);
    }

    /**
     * Creates a new AgentConnection with custom timeout and authentication.
     *
     * @param agentDetails the resolved agent details
     * @param ansHttpClient the verifying HTTP client (performs verification outside TLS handshake)
     * @param timeout the default timeout for requests
     * @param httpAuthHeadersProvider the authentication provider (may be null)
     */
    public AgentConnection(AgentDetails agentDetails, AnsHttpClient ansHttpClient, Duration timeout,
                           HttpAuthHeadersProvider httpAuthHeadersProvider) {
        this.agentDetails = Objects.requireNonNull(agentDetails,
            "Agent details cannot be null");
        this.ansHttpClient = Objects.requireNonNull(ansHttpClient,
            "ANS HTTP client cannot be null");
        this.timeout = Objects.requireNonNull(timeout, "Timeout cannot be null");
        this.httpAuthHeadersProvider = httpAuthHeadersProvider;

        LOGGER.debug("Created connection to: {}", agentDetails.getAgentHost());
    }

    /**
     * Returns an HTTP-API client configured for the specified base URL.
     *
     * <p>The HTTP-API client allows making REST calls to the remote agent.
     * All requests are verified using the verification policy configured
     * during connection.</p>
     *
     * @param baseUrl the base URL to connect to
     * @return the HTTP-API client
     */
    public HttpApiClient httpApiAt(String baseUrl) {
        return new HttpApiClient(ansHttpClient, baseUrl, timeout, httpAuthHeadersProvider);
    }

    /**
     * Returns the agent details.
     *
     * @return the resolved agent details
     */
    public AgentDetails getAgentDetails() {
        return agentDetails;
    }

    /**
     * Returns the ANS name of the connected agent.
     *
     * @return the ANS name (e.g., "ans://v1.0.0.agent.example.com")
     */
    public String getAnsName() {
        return agentDetails.getAnsName();
    }

    /**
     * Returns the agent host.
     *
     * @return the agent host (e.g., "agent.example.com")
     */
    public String getAgentHost() {
        return agentDetails.getAgentHost();
    }

    /**
     * Returns the agent version.
     *
     * @return the agent version
     */
    public String getVersion() {
        return agentDetails.getVersion();
    }

    /**
     * Checks if the agent supports the specified protocol.
     *
     * @param protocol the protocol to check (e.g., "A2A", "MCP", "HTTP_API")
     * @return true if the agent supports the protocol
     */
    public boolean supportsProtocol(String protocol) {
        return getEndpointUrl(protocol).isPresent();
    }

    /**
     * Returns the endpoint URL for the specified protocol.
     *
     * @param protocol the protocol (e.g., "A2A", "MCP", "HTTP_API")
     * @return the endpoint URL, or empty if not supported
     */
    public Optional<String> getEndpointUrl(String protocol) {
        return agentDetails.getEndpoints().stream()
            .filter(endpoint -> matchesProtocol(endpoint.getProtocol(), protocol))
            .map(AgentEndpoint::getAgentUrl)
            .map(URI::toString)
            .findFirst();
    }

    /**
     * Returns the metadata URL for the specified protocol.
     *
     * @param protocol the protocol
     * @return the metadata URL, or empty if not available
     */
    public Optional<String> getMetadataUrl(String protocol) {
        return agentDetails.getEndpoints().stream()
            .filter(endpoint -> matchesProtocol(endpoint.getProtocol(), protocol))
            .map(AgentEndpoint::getMetaDataUrl)
            .filter(Objects::nonNull)
            .map(URI::toString)
            .findFirst();
    }

    /**
     * Checks if a Protocol enum matches the protocol string.
     */
    private boolean matchesProtocol(AgentEndpoint.ProtocolEnum endpointProtocol, String protocolStr) {
        if (endpointProtocol == null || protocolStr == null) {
            return false;
        }
        // Handle both enum name (HTTP_API) and value (HTTP-API)
        return protocolStr.equals(endpointProtocol.name())
            || protocolStr.equals(endpointProtocol.getValue());
    }

    /**
     * Returns the underlying HTTP client.
     *
     * <p>Use this for advanced scenarios where you need direct access to the
     * underlying HTTP client. Note that using this directly bypasses
     * post-handshake verification.</p>
     *
     * @return the underlying HTTP client
     */
    public HttpClient getHttpClient() {
        return ansHttpClient.getDelegate();
    }

    /**
     * Returns the ANS HTTP client.
     *
     * <p>The ansHttpClient client performs DANE/Badge verification
     * outside the TLS handshake.</p>
     *
     * @return the ANS HTTP client
     */
    public AnsHttpClient getAnsHttpClient() {
        return ansHttpClient;
    }

    @Override
    public String toString() {
        return "AgentConnection{" +
            "ansName='" + agentDetails.getAnsName() + '\'' +
            ", agentHost='" + agentDetails.getAgentHost() + '\'' +
            ", version='" + agentDetails.getVersion() + '\'' +
            '}';
    }
}