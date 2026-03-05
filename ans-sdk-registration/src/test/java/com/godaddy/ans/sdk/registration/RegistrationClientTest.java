package com.godaddy.ans.sdk.registration;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.godaddy.ans.sdk.auth.JwtCredentialsProvider;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsValidationException;
import com.godaddy.ans.sdk.model.generated.AgentDetails;
import com.godaddy.ans.sdk.model.generated.AgentEndpoint;
import com.godaddy.ans.sdk.model.generated.AgentLifecycleStatus;
import com.godaddy.ans.sdk.model.generated.AgentRegistrationRequest;
import com.godaddy.ans.sdk.model.generated.AgentRevocationRequest;
import com.godaddy.ans.sdk.model.generated.AgentRevocationResponse;
import com.godaddy.ans.sdk.model.generated.AgentStatus;
import com.godaddy.ans.sdk.model.generated.RegistrationPending;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.net.URI;
import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for RegistrationClient.
 */
@WireMockTest
class RegistrationClientTest {

    private static final String TEST_JWT_TOKEN = "test-jwt-token";
    private static final String TEST_AGENT_ID = "550e8400-e29b-41d4-a716-446655440000";

    // ==================== Builder Tests ====================

    @Test
    @DisplayName("Should build client with environment")
    void shouldBuildClientWithEnvironment() {
        RegistrationClient client = RegistrationClient.builder()
            .environment(Environment.OTE)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThat(client).isNotNull();
        assertThat(client.getConfiguration().getEnvironment()).isEqualTo(Environment.OTE);
        assertThat(client.getConfiguration().getBaseUrl()).isEqualTo("https://api.ote-godaddy.com");
    }

    @Test
    @DisplayName("Should build client with custom base URL")
    void shouldBuildClientWithCustomBaseUrl(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThat(client).isNotNull();
        assertThat(client.getConfiguration().getBaseUrl()).isEqualTo(baseUrl);
    }

    @Test
    @DisplayName("Should build client with custom timeouts")
    void shouldBuildClientWithCustomTimeouts() {
        RegistrationClient client = RegistrationClient.builder()
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
        RegistrationClient client = RegistrationClient.builder()
            .environment(Environment.OTE)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .enableRetry(5)
            .build();

        assertThat(client.getConfiguration().isRetryEnabled()).isTrue();
        assertThat(client.getConfiguration().getMaxRetries()).isEqualTo(5);
    }

    @Test
    @DisplayName("Should throw exception when credentials provider is null")
    void shouldThrowExceptionWhenCredentialsProviderIsNull() {
        assertThatThrownBy(() -> RegistrationClient.builder()
            .environment(Environment.OTE)
            .build())
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Should expose certificate service")
    void shouldExposeCertificateService() {
        RegistrationClient client = RegistrationClient.builder()
            .environment(Environment.OTE)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThat(client.certificates()).isNotNull();
    }

    // ==================== Registration Tests ====================

    @Test
    @DisplayName("Should register agent successfully")
    void shouldRegisterAgentSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Stub the initial registration POST
        stubFor(post(urlEqualTo("/v1/agents/register"))
            .willReturn(aResponse()
                .withStatus(202)
                .withHeader("Content-Type", "application/json")
                .withBody(registrationPendingResponse())));

        // Stub the follow-up GET for AgentDetails
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRegistrationRequest request = new AgentRegistrationRequest()
            .agentDisplayName("Test Agent")
            .version("1.0.0")
            .agentHost("test-agent.example.com")
            .addEndpointsItem(new AgentEndpoint()
                .protocol(AgentEndpoint.ProtocolEnum.A2A)
                .agentUrl(URI.create("https://test-agent.example.com/a2a")))
            .identityCsrPEM("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----")
            .serverCsrPEM("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----");

        AgentDetails result = client.registerAgent(request);

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
        assertThat(result.getAnsName()).isEqualTo("ans://v1.0.0.test-agent.example.com");
        assertThat(result.getRegistrationPending()).isNotNull();
        assertThat(result.getRegistrationPending().getStatus()).isEqualTo(RegistrationPending.StatusEnum.VALIDATION);
        assertThat(result.getRegistrationPending().getChallenges()).hasSize(1);
        assertThat(result.getRegistrationPending().getNextSteps()).hasSize(1);

        verify(postRequestedFor(urlEqualTo("/v1/agents/register"))
            .withRequestBody(containing("\"agentDisplayName\":\"Test Agent\""))
            .withHeader("Authorization", equalTo("sso-jwt " + TEST_JWT_TOKEN)));
    }

    @Test
    @DisplayName("Should throw AnsValidationException on 422")
    void shouldThrowValidationExceptionOn422(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/register"))
            .willReturn(aResponse()
                .withStatus(422)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"INVALID_ARGUMENT\","
                    + "\"message\":\"Invalid version format\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRegistrationRequest request = new AgentRegistrationRequest()
            .agentDisplayName("Test Agent")
            .version("invalid")
            .agentHost("test-agent.example.com")
            .addEndpointsItem(new AgentEndpoint()
                .protocol(AgentEndpoint.ProtocolEnum.A2A)
                .agentUrl(URI.create("https://test-agent.example.com/a2a")))
            .identityCsrPEM("test-csr")
            .serverCsrPEM("test-csr");

        assertThatThrownBy(() -> client.registerAgent(request))
            .isInstanceOf(AnsValidationException.class)
            .hasMessageContaining("Validation error");
    }

    // ==================== Verify ACME Tests ====================

    @Test
    @DisplayName("Should verify ACME successfully")
    void shouldVerifyAcmeSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/verify-acme"))
            .willReturn(aResponse()
                .withStatus(202)
                .withHeader("Content-Type", "application/json")
                .withBody(agentStatusResponse(AgentLifecycleStatus.PENDING_DNS))));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentStatus result = client.verifyAcme(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.PENDING_DNS);
    }

    @Test
    @DisplayName("Should throw AnsNotFoundException when agent not found for verifyAcme")
    void shouldThrowNotFoundExceptionForVerifyAcme(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/verify-acme"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.verifyAcme(TEST_AGENT_ID))
            .isInstanceOf(AnsNotFoundException.class)
            .hasMessageContaining("not found");
    }

    // ==================== Verify DNS Tests ====================

    @Test
    @DisplayName("Should verify DNS successfully")
    void shouldVerifyDnsSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/verify-dns"))
            .willReturn(aResponse()
                .withStatus(202)
                .withHeader("Content-Type", "application/json")
                .withBody(agentStatusResponse(AgentLifecycleStatus.ACTIVE))));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentStatus result = client.verifyDns(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.ACTIVE);
    }

    @Test
    @DisplayName("Should throw AnsAuthenticationException on 401 for verifyDns")
    void shouldThrowAuthExceptionForVerifyDns(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/verify-dns"))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"UNAUTHORIZED\",\"message\":\"Invalid token\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.verifyDns(TEST_AGENT_ID))
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Authentication failed");
    }

    // ==================== Revoke Agent Tests ====================

    @Test
    @DisplayName("Should revoke agent successfully with full request")
    void shouldRevokeAgentSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(revocationResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRevocationRequest request = new AgentRevocationRequest()
            .reason(AgentRevocationRequest.ReasonEnum.CESSATION_OF_OPERATION)
            .comments("Agent being decommissioned");

        AgentRevocationResponse result = client.revokeAgent(TEST_AGENT_ID, request);

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).hasToString(TEST_AGENT_ID);
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.REVOKED);
        assertThat(result.getReason()).isEqualTo(AgentRevocationResponse.ReasonEnum.CESSATION_OF_OPERATION);
        assertThat(result.getDnsRecordsToRemove()).hasSize(3);

        verify(postRequestedFor(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .withRequestBody(containing("\"reason\":\"CESSATION_OF_OPERATION\""))
            .withRequestBody(containing("\"comments\":\"Agent being decommissioned\""))
            .withHeader("Authorization", equalTo("sso-jwt " + TEST_JWT_TOKEN)));
    }

    @Test
    @DisplayName("Should revoke agent with just reason code")
    void shouldRevokeAgentWithJustReason(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(revocationResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRevocationResponse result = client.revokeAgent(TEST_AGENT_ID,
                AgentRevocationRequest.ReasonEnum.KEY_COMPROMISE);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.REVOKED);

        verify(postRequestedFor(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .withRequestBody(containing("\"reason\":\"KEY_COMPROMISE\"")));
    }

    @Test
    @DisplayName("Should throw AnsNotFoundException when agent not found for revoke")
    void shouldThrowNotFoundExceptionForRevoke(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.revokeAgent(TEST_AGENT_ID,
                AgentRevocationRequest.ReasonEnum.CESSATION_OF_OPERATION))
            .isInstanceOf(AnsNotFoundException.class)
            .hasMessageContaining("not found");
    }

    @Test
    @DisplayName("Should throw AnsValidationException when agent already revoked")
    void shouldThrowValidationExceptionWhenAlreadyRevoked(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(422)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"INVALID_ARGUMENT\","
                    + "\"message\":\"Agent is already in REVOKED state\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.revokeAgent(TEST_AGENT_ID,
                AgentRevocationRequest.ReasonEnum.CESSATION_OF_OPERATION))
            .isInstanceOf(AnsValidationException.class)
            .hasMessageContaining("Validation error");
    }

    @Test
    @DisplayName("Should throw AnsValidationException for pending validation agent")
    void shouldThrowValidationExceptionForPendingValidation(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(422)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"INVALID_ARGUMENT\","
                    + "\"message\":\"Cannot revoke agent in PENDING_VALIDATION state\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.revokeAgent(TEST_AGENT_ID,
                AgentRevocationRequest.ReasonEnum.CESSATION_OF_OPERATION))
            .isInstanceOf(AnsValidationException.class)
            .hasMessageContaining("Validation error");
    }

    // ==================== Get Agent Tests ====================

    @Test
    @DisplayName("Should get agent by ID successfully")
    void shouldGetAgentByIdSuccessfully(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentDetails result = client.getAgent(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
        assertThat(result.getAnsName()).isEqualTo("ans://v1.0.0.test-agent.example.com");
    }

    @Test
    @DisplayName("Should throw AnsNotFoundException when agent not found")
    void shouldThrowNotFoundExceptionWhenAgentNotFound(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"status\":\"error\",\"code\":\"NOT_FOUND\",\"message\":\"Agent not found\"}")));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        assertThatThrownBy(() -> client.getAgent(TEST_AGENT_ID))
            .isInstanceOf(AnsNotFoundException.class)
            .hasMessageContaining("not found");
    }

    // ==================== Async Tests ====================

    @Test
    @DisplayName("Should register agent asynchronously")
    void shouldRegisterAgentAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/register"))
            .willReturn(aResponse()
                .withStatus(202)
                .withHeader("Content-Type", "application/json")
                .withBody(registrationPendingResponse())));

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(agentDetailsResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRegistrationRequest request = new AgentRegistrationRequest()
            .agentDisplayName("Test Agent")
            .version("1.0.0")
            .agentHost("test-agent.example.com")
            .addEndpointsItem(new AgentEndpoint()
                .protocol(AgentEndpoint.ProtocolEnum.A2A)
                .agentUrl(URI.create("https://test-agent.example.com/a2a")))
            .identityCsrPEM("test-csr")
            .serverCsrPEM("test-csr");

        AgentDetails result = client.registerAgentAsync(request).get();

        assertThat(result).isNotNull();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
    }

    @Test
    @DisplayName("Should verify ACME asynchronously")
    void shouldVerifyAcmeAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/verify-acme"))
            .willReturn(aResponse()
                .withStatus(202)
                .withHeader("Content-Type", "application/json")
                .withBody(agentStatusResponse(AgentLifecycleStatus.PENDING_DNS))));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentStatus result = client.verifyAcmeAsync(TEST_AGENT_ID).get();

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.PENDING_DNS);
    }

    @Test
    @DisplayName("Should verify DNS asynchronously")
    void shouldVerifyDnsAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/verify-dns"))
            .willReturn(aResponse()
                .withStatus(202)
                .withHeader("Content-Type", "application/json")
                .withBody(agentStatusResponse(AgentLifecycleStatus.ACTIVE))));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentStatus result = client.verifyDnsAsync(TEST_AGENT_ID).get();

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.ACTIVE);
    }

    @Test
    @DisplayName("Should revoke agent asynchronously with request")
    void shouldRevokeAgentAsyncWithRequest(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(revocationResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRevocationRequest request = new AgentRevocationRequest()
            .reason(AgentRevocationRequest.ReasonEnum.CESSATION_OF_OPERATION);

        AgentRevocationResponse result = client.revokeAgentAsync(TEST_AGENT_ID, request).get();

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.REVOKED);
    }

    @Test
    @DisplayName("Should revoke agent asynchronously with reason")
    void shouldRevokeAgentAsyncWithReason(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(post(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/revoke"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(revocationResponse())));

        RegistrationClient client = RegistrationClient.builder()
            .baseUrl(baseUrl)
            .credentialsProvider(new JwtCredentialsProvider(TEST_JWT_TOKEN))
            .build();

        AgentRevocationResponse result = client.revokeAgentAsync(TEST_AGENT_ID,
                AgentRevocationRequest.ReasonEnum.KEY_COMPROMISE).get();

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo(AgentLifecycleStatus.REVOKED);
    }

    // ==================== Helper Methods ====================

    private String registrationPendingResponse() {
        return """
            {
                "status": "PENDING_VALIDATION",
                "ansName": "ans://v1.0.0.test-agent.example.com",
                "nextSteps": [
                    {
                        "action": "CONFIGURE_DNS",
                        "description": "Configure DNS TXT record for ACME challenge",
                        "estimatedTimeMinutes": 5
                    }
                ],
                "challenges": [
                    {
                        "type": "DNS_01",
                        "token": "abc123",
                        "keyAuthorization": "abc123.xyz789",
                        "dnsRecord": {
                            "name": "_acme-challenge.test-agent.example.com",
                            "type": "TXT",
                            "value": "xyz789"
                        }
                    }
                ],
                "expiresAt": "2024-01-15T12:00:00Z",
                "links": [
                    {
                        "rel": "self",
                        "href": "/v1/agents/550e8400-e29b-41d4-a716-446655440000"
                    }
                ]
            }
            """;
    }

    private String agentDetailsResponse() {
        return """
            {
                "agentId": "550e8400-e29b-41d4-a716-446655440000",
                "agentDisplayName": "Test Agent",
                "version": "1.0.0",
                "agentHost": "test-agent.example.com",
                "ansName": "ans://v1.0.0.test-agent.example.com",
                "agentStatus": "PENDING_VALIDATION",
                "endpoints": [
                    {
                        "protocol": "A2A",
                        "agentUrl": "https://test-agent.example.com/a2a"
                    }
                ],
                "registrationPending": {
                    "status": "PENDING_VALIDATION",
                    "ansName": "ans://v1.0.0.test-agent.example.com",
                    "nextSteps": [
                        {
                            "action": "CONFIGURE_DNS",
                            "description": "Configure DNS TXT record for ACME challenge",
                            "estimatedTimeMinutes": 5
                        }
                    ],
                    "challenges": [
                        {
                            "type": "DNS_01",
                            "token": "abc123",
                            "keyAuthorization": "abc123.xyz789",
                            "dnsRecord": {
                                "name": "_acme-challenge.test-agent.example.com",
                                "type": "TXT",
                                "value": "xyz789"
                            }
                        }
                    ],
                    "expiresAt": "2024-01-15T12:00:00Z"
                },
                "links": [
                    {
                        "rel": "self",
                        "href": "/v1/agents/550e8400-e29b-41d4-a716-446655440000"
                    }
                ]
            }
            """;
    }

    private String agentStatusResponse(AgentLifecycleStatus status) {
        return String.format("""
            {
                "status": "%s",
                "phase": "DOMAIN_VALIDATION",
                "completedSteps": ["REGISTRATION_SUBMITTED"],
                "pendingSteps": ["DNS_VERIFICATION"],
                "createdAt": "2024-01-15T10:00:00Z",
                "updatedAt": "2024-01-15T10:30:00Z"
            }
            """, status.getValue());
    }

    private String revocationResponse() {
        return """
            {
                "agentId": "550e8400-e29b-41d4-a716-446655440000",
                "ansName": "ans://v1.0.0.test-agent.example.com",
                "status": "REVOKED",
                "revokedAt": "2024-01-15T12:00:00Z",
                "reason": "CESSATION_OF_OPERATION",
                "dnsRecordsToRemove": [
                    {
                        "name": "_ra-badge.test-agent.example.com",
                        "type": "TXT",
                        "value": "v=ans1; url=https://transparency.ans.godaddy.com/v1/agents/550e8400-e29b-41d4-a716-446655440000",
                        "purpose": "BADGE"
                    },
                    {
                        "name": "_ans.test-agent.example.com",
                        "type": "TXT",
                        "value": "v=ans1; version=1.0.0; url=https://test-agent.example.com/agent-card.json",
                        "purpose": "TRUST"
                    },
                    {
                        "name": "_443._tcp.test-agent.example.com",
                        "type": "TLSA",
                        "value": "3 1 1 abc123...",
                        "purpose": "CERTIFICATE_BINDING"
                    }
                ],
                "links": [
                    {
                        "rel": "self",
                        "href": "https://api.ans.example.org/v1/agents/550e8400-e29b-41d4-a716-446655440000"
                    },
                    {
                        "rel": "transparency-log",
                        "href": "https://transparency.ans.godaddy.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"
                    }
                ]
            }
            """;
    }
}