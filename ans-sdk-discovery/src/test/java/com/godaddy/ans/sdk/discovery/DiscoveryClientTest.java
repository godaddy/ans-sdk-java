package com.godaddy.ans.sdk.discovery;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentLifecycleStatus;
import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.exception.AnsValidationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for DiscoveryClient.
 */
@WireMockTest
class DiscoveryClientTest {

    private static final String TEST_JWT_TOKEN = "test-jwt-token";
    private static final String TEST_AGENT_HOST = "booking-agent.example.com";
    private static final String TEST_AGENT_ID = "550e8400-e29b-41d4-a716-446655440000";

    // ==================== Builder Tests ====================

    @Test
    @DisplayName("Should build client with OTE environment")
    void shouldBuildClientWithOteEnvironment() {
        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThat(client).isNotNull();
        assertThat(client.getConfiguration().getEnvironment()).isEqualTo(Environment.OTE);
        assertThat(client.getConfiguration().getBaseUrl()).isEqualTo("https://api.ote-godaddy.com");
    }

    @Test
    @DisplayName("Should build client with PROD environment")
    void shouldBuildClientWithProdEnvironment() {
        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.PROD)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThat(client.getConfiguration().getBaseUrl()).isEqualTo("https://api.godaddy.com");
    }

    @Test
    @DisplayName("Should build client with custom base URL")
    void shouldBuildClientWithCustomBaseUrl(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThat(client).isNotNull();
        assertThat(client.getConfiguration().getBaseUrl()).isEqualTo(baseUrl);
    }

    @Test
    @DisplayName("Should build client with custom timeouts")
    void shouldBuildClientWithCustomTimeouts() {
        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(15))
            .build();

        assertThat(client.getConfiguration().getConnectTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(client.getConfiguration().getReadTimeout()).isEqualTo(Duration.ofSeconds(15));
    }

    @Test
    @DisplayName("Should build client with retry enabled")
    void shouldBuildClientWithRetryEnabled() {
        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .enableRetry(3)
            .build();

        assertThat(client.getConfiguration().isRetryEnabled()).isTrue();
        assertThat(client.getConfiguration().getMaxRetries()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should throw exception when credentials provider is null")
    void shouldThrowExceptionWhenCredentialsProviderIsNull() {
        assertThatThrownBy(() -> DiscoveryClient.builder()
            .environment(Environment.OTE)
            .build())
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Should build client with pre-built configuration")
    void shouldBuildClientWithPreBuiltConfiguration() {
        AnsConfiguration prebuilt = AnsConfiguration.builder()
            .environment(Environment.PROD)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .baseUrl("https://custom.example.com")
            .build();

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .configuration(prebuilt)
            .build();

        assertThat(client.getConfiguration()).isSameAs(prebuilt);
        assertThat(client.getConfiguration().getBaseUrl()).isEqualTo("https://custom.example.com");
    }

    // ==================== Resolution Success Tests ====================

    @Test
    @DisplayName("Should resolve agent successfully")
    void shouldResolveAgentSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Mock resolution endpoint
        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(resolutionResponse(baseUrl))));

        // Mock agent details endpoint
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.resolve(TEST_AGENT_HOST, "^1.0.0");

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
        assertThat(result.getAgentHost()).isEqualTo(TEST_AGENT_HOST);
        assertThat(result.getAgentDisplayName()).isEqualTo("Booking Agent");
        assertThat(result.getAgentDescription()).isEqualTo("A booking agent for scheduling appointments");
        assertThat(result.getVersion()).isEqualTo("1.0.0");
        assertThat(result.getAnsName()).isEqualTo("ans://v1.0.0." + TEST_AGENT_HOST);
        assertThat(result.getAgentStatus()).isEqualTo(AgentLifecycleStatus.ACTIVE);
        assertThat(result.getRegistrationTimestamp()).isNotNull();
        assertThat(result.getLastRenewalTimestamp()).isNotNull();

        // Verify endpoints
        assertThat(result.getEndpoints()).hasSize(1);
        var endpoint = result.getEndpoints().get(0);
        assertThat(endpoint.getProtocol().getValue()).isEqualTo("A2A");
        assertThat(endpoint.getAgentUrl().toString()).isEqualTo("https://booking-agent.example.com/a2a");
        assertThat(endpoint.getMetaDataUrl().toString()).isEqualTo("https://booking-agent.example.com/.well-known/agent.json");
        assertThat(endpoint.getDocumentationUrl().toString()).isEqualTo("https://docs.booking-agent.example.com");
        assertThat(endpoint.getFunctions()).hasSize(2);
        assertThat(endpoint.getFunctions().get(0).getId()).isEqualTo("book_appointment");
        assertThat(endpoint.getFunctions().get(0).getName()).isEqualTo("Book Appointment");
        assertThat(endpoint.getFunctions().get(0).getTags()).containsExactly("booking", "scheduling");

        // Verify links
        assertThat(result.getLinks()).hasSize(1);
        assertThat(result.getLinks().get(0).getRel()).isEqualTo("self");
        assertThat(result.getLinks().get(0).getHref().toString()).contains(TEST_AGENT_ID);

        // Verify the request was made with correct body
        verify(postRequestedFor(urlEqualTo("/v1/agents/resolution"))
            .withRequestBody(containing("\"agentHost\":\"" + TEST_AGENT_HOST + "\""))
            .withRequestBody(containing("\"version\":\"^1.0.0\""))
            .withHeader("Authorization", equalTo("sso-jwt " + TEST_JWT_TOKEN)));
    }

    @Test
    @DisplayName("Should resolve agent without version (defaults to wildcard)")
    void shouldResolveAgentWithoutVersion(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(resolutionResponse(baseUrl))));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.resolve(TEST_AGENT_HOST);

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);

        // Verify wildcard version was used
        verify(postRequestedFor(urlEqualTo("/v1/agents/resolution"))
            .withRequestBody(containing("\"version\":\"*\"")));
    }

    @Test
    @DisplayName("Should resolve agent asynchronously")
    void shouldResolveAgentAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(resolutionResponse(baseUrl))));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        CompletableFuture<AgentDetails> future = client.resolveAsync(TEST_AGENT_HOST, "^1.0.0");
        AgentDetails result = future.get();

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
    }

    // ==================== Resolution Error Tests ====================

    @Test
    @DisplayName("Should throw AnsNotFoundException when agent not found (404)")
    void shouldThrowNotFoundExceptionWhen404(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsNotFoundException.class)
            .hasMessageContaining("Agent not found");
    }

    @Test
    @DisplayName("Should throw AnsAuthenticationException when unauthorized (401)")
    void shouldThrowAuthExceptionWhen401(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"UNAUTHORIZED\",\"message\":\"Invalid credentials\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Authentication failed");
    }

    @Test
    @DisplayName("Should throw AnsAuthenticationException when forbidden (403)")
    void shouldThrowAuthExceptionWhen403(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(403)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"FORBIDDEN\",\"message\":\"Access denied\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Authentication failed");
    }

    @Test
    @DisplayName("Should throw AnsValidationException when validation fails (422)")
    void shouldThrowValidationExceptionWhen422(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(422)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"INVALID_ARGUMENT\","
                        + "\"message\":\"Invalid version format\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST, "invalid-version"))
            .isInstanceOf(AnsValidationException.class)
            .hasMessageContaining("Validation error");
    }

    @Test
    @DisplayName("Should throw AnsServerException when server error (500)")
    void shouldThrowServerExceptionWhen500(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"INTERNAL_ERROR\",\"message\":\"Internal server error\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Server error");
    }

    @Test
    @DisplayName("Should throw AnsServerException when agent-details link is missing")
    void shouldThrowServerExceptionWhenLinkMissing(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Return response without agent-details link
        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"ansName\":\"ans://v1.0.0.booking-agent.example.com\",\"links\":[]}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("missing agent-details link");
    }

    @Test
    @DisplayName("Should throw exception in async and wrap it properly")
    void shouldWrapExceptionInAsync(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        CompletableFuture<AgentDetails> future = client.resolveAsync(TEST_AGENT_HOST);

        assertThatThrownBy(future::get)
            .isInstanceOf(ExecutionException.class)
            .hasCauseInstanceOf(AnsNotFoundException.class);
    }

    // ==================== GetAgent Tests ====================

    @Test
    @DisplayName("Should get agent by ID successfully")
    void shouldGetAgentByIdSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.getAgent(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
        assertThat(result.getAgentHost()).isEqualTo(TEST_AGENT_HOST);
        assertThat(result.getVersion()).isEqualTo("1.0.0");
        assertThat(result.getAgentStatus()).isEqualTo(AgentLifecycleStatus.ACTIVE);
        assertThat(result.getEndpoints()).hasSize(1);
    }

    @Test
    @DisplayName("Should throw AnsNotFoundException when getting non-existent agent")
    void shouldThrowNotFoundWhenGettingNonExistentAgent(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        String nonExistentId = "00000000-0000-0000-0000-000000000000";

        stubFor(get(urlEqualTo("/v1/agents/" + nonExistentId))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.getAgent(nonExistentId))
            .isInstanceOf(AnsNotFoundException.class)
            .hasMessageContaining("Agent not found");
    }

    @Test
    @DisplayName("Should throw AnsAuthenticationException when unauthorized to get agent")
    void shouldThrowAuthExceptionWhenUnauthorizedToGetAgent(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"UNAUTHORIZED\",\"message\":\"Invalid token\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.getAgent(TEST_AGENT_ID))
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Authentication failed");
    }

    @Test
    @DisplayName("Should get agent asynchronously")
    void shouldGetAgentAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        CompletableFuture<AgentDetails> future = client.getAgentAsync(TEST_AGENT_ID);
        AgentDetails result = future.get();

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
    }

    @Test
    @DisplayName("Should wrap exception in async getAgent")
    void shouldWrapExceptionInAsyncGetAgent(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        CompletableFuture<AgentDetails> future = client.getAgentAsync(TEST_AGENT_ID);

        assertThatThrownBy(future::get)
            .isInstanceOf(ExecutionException.class)
            .hasCauseInstanceOf(AnsNotFoundException.class);
    }

    // ==================== Additional Error Path Tests ====================

    @Test
    @DisplayName("Should handle relative href in resolution response")
    void shouldHandleRelativeHrefInResolutionResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Return response with relative path (no http prefix)
        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(String.format("""
                    {
                        "ansName": "ans://v1.0.0.%s",
                        "links": [
                            {
                                "href": "/v1/agents/%s",
                                "rel": "agent-details"
                            }
                        ]
                    }
                    """, TEST_AGENT_HOST, TEST_AGENT_ID))));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.resolve(TEST_AGENT_HOST);

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
    }

    @Test
    @DisplayName("Should throw AnsServerException for malformed resolution JSON")
    void shouldThrowServerExceptionForMalformedResolutionJson(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{ invalid json }")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Failed to parse resolution response");
    }

    @Test
    @DisplayName("Should throw AnsServerException for malformed agent details JSON")
    void shouldThrowServerExceptionForMalformedAgentDetailsJson(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(resolutionResponse(baseUrl))));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{ not valid json }")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Failed to parse agent details");
    }

    @Test
    @DisplayName("Should throw AnsServerException for unexpected 4xx error")
    void shouldThrowServerExceptionForUnexpected4xxError(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(400)  // Bad Request - not specifically handled
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"message\":\"Bad request\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Unexpected error (400)");
    }

    @Test
    @DisplayName("Should handle null version in resolve")
    void shouldHandleNullVersionInResolve(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(resolutionResponse(baseUrl))));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.resolve(TEST_AGENT_HOST, null);

        assertThat(result).isNotNull();

        // Verify wildcard version was used
        verify(postRequestedFor(urlEqualTo("/v1/agents/resolution"))
            .withRequestBody(containing("\"version\":\"*\"")));
    }

    @Test
    @DisplayName("Should handle empty version string in resolve")
    void shouldHandleEmptyVersionStringInResolve(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(resolutionResponse(baseUrl))));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.resolve(TEST_AGENT_HOST, "");

        assertThat(result).isNotNull();

        // Verify wildcard version was used
        verify(postRequestedFor(urlEqualTo("/v1/agents/resolution"))
            .withRequestBody(containing("\"version\":\"*\"")));
    }

    @Test
    @DisplayName("Should include X-Request-Id in error response when available")
    void shouldIncludeRequestIdInErrorResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        String requestId = "test-request-id-123";

        stubFor(post(urlEqualTo("/v1/agents/resolution"))
            .willReturn(aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Request-Id", requestId)
                .withBody("{\"status\":\"error\",\"message\":\"Internal error\"}")));

        DiscoveryClient client = DiscoveryClient.builder()
            .environment(Environment.OTE)
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.resolve(TEST_AGENT_HOST))
            .isInstanceOf(AnsServerException.class)
            .satisfies(e -> {
                AnsServerException serverException = (AnsServerException) e;
                assertThat(serverException.getRequestId()).isEqualTo(requestId);
            });
    }

    // ==================== Helper Methods ====================

    private String resolutionResponse(String baseUrl) {
        return String.format("""
            {
                "ansName": "ans://v1.0.0.%s",
                "links": [
                    {
                        "href": "%s/v1/agents/%s",
                        "rel": "agent-details"
                    }
                ]
            }
            """, TEST_AGENT_HOST, baseUrl, TEST_AGENT_ID);
    }

    private String agentDetailsResponse() {
        return String.format("""
            {
                "agentId": "%s",
                "agentHost": "%s",
                "agentDisplayName": "Booking Agent",
                "agentDescription": "A booking agent for scheduling appointments",
                "version": "1.0.0",
                "ansName": "ans://v1.0.0.%s",
                "agentStatus": "ACTIVE",
                "registrationTimestamp": "2024-01-15T10:30:00Z",
                "lastRenewalTimestamp": "2024-06-15T10:30:00Z",
                "endpoints": [
                    {
                        "agentUrl": "https://booking-agent.example.com/a2a",
                        "protocol": "A2A",
                        "metaDataUrl": "https://booking-agent.example.com/.well-known/agent.json",
                        "documentationUrl": "https://docs.booking-agent.example.com",
                        "functions": [
                            {
                                "id": "book_appointment",
                                "name": "Book Appointment",
                                "tags": ["booking", "scheduling"]
                            },
                            {
                                "id": "cancel_appointment",
                                "name": "Cancel Appointment",
                                "tags": ["booking"]
                            }
                        ]
                    }
                ],
                "links": [
                    {
                        "rel": "self",
                        "href": "https://api.godaddy.com/v1/agents/%s"
                    }
                ]
            }
            """, TEST_AGENT_ID, TEST_AGENT_HOST, TEST_AGENT_HOST, TEST_AGENT_ID);
    }
}