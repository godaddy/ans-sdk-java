package com.godaddy.ans.sdk.transparency;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.transparency.model.AgentAuditParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointResponse;
import com.godaddy.ans.sdk.transparency.model.EventTypeV1;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryParams;
import com.godaddy.ans.sdk.transparency.model.CheckpointHistoryResponse;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogAudit;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogV1;
import com.godaddy.ans.sdk.transparency.scitt.TrustedDomainRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class TransparencyClientTest {

    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";

    @BeforeAll
    static void setUpClass() {
        // Include localhost for WireMock tests along with production domains
        System.setProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY,
            "transparency.ans.godaddy.com,transparency.ans.ote-godaddy.com,localhost");
    }

    @AfterAll
    static void tearDownClass() {
        System.clearProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY);
    }

    @Test
    @DisplayName("Should retrieve agent transparency log with V1 schema")
    void shouldRetrieveAgentTransparencyLogV1(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Schema-Version", "V1")
                .withBody(v1TransparencyLogResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLog result = client.getAgentTransparencyLog(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo("ACTIVE");
        assertThat(result.isV1()).isTrue();
        assertThat(result.getV1Payload()).isNotNull();

        TransparencyLogV1 v1 = result.getV1Payload();
        assertThat(v1.getLogId()).isEqualTo("log-123");
        assertThat(v1.getEventType()).isEqualTo(EventTypeV1.AGENT_REGISTERED);
        assertThat(v1.getAnsName()).isEqualTo("ans://v1.0.0.agent.example.com");

        // Test convenience methods
        assertThat(result.getServerCertFingerprint()).isEqualTo("SHA256:a1b2c3d4");
        assertThat(result.getIdentityCertFingerprint()).isEqualTo("SHA256:e5f6g7h8");
        assertThat(result.getAnsName()).isEqualTo("ans://v1.0.0.agent.example.com");
        assertThat(result.getAgentHost()).isEqualTo("agent.example.com");
    }

    @Test
    @DisplayName("Should retrieve agent transparency log with V0 schema")
    void shouldRetrieveAgentTransparencyLogV0(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(v0TransparencyLogResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLog result = client.getAgentTransparencyLog(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.isV0()).isTrue();
        assertThat(result.getV0Payload()).isNotNull();

        // Test V0 convenience methods
        assertThat(result.getServerCertFingerprint()).isEqualTo("SHA256:server123");
        assertThat(result.getIdentityCertFingerprint()).isEqualTo("SHA256:client456");
        assertThat(result.getAgentHost()).isEqualTo("agent.example.com");
    }

    @Test
    @DisplayName("Should throw AnsNotFoundException when agent not found")
    void shouldThrowNotFoundWhenAgentNotFound(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/unknown-id"))
            .willReturn(aResponse()
                .withStatus(404)
                .withBody("{\"message\": \"Agent not found\"}")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getAgentTransparencyLog("unknown-id"))
            .isInstanceOf(AnsNotFoundException.class);
    }

    @Test
    @DisplayName("Should retrieve checkpoint")
    void shouldRetrieveCheckpoint(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/checkpoint"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(checkpointResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        CheckpointResponse result = client.getCheckpoint();

        assertThat(result).isNotNull();
        assertThat(result.getLogSize()).isEqualTo(1000L);
        assertThat(result.getTreeHeight()).isEqualTo(10);
        assertThat(result.getRootHash()).isEqualTo("abc123");
    }

    @Test
    @DisplayName("Should retrieve agent audit with pagination")
    void shouldRetrieveAgentAuditWithPagination(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/audit?offset=10&limit=5"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(auditResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        AgentAuditParams params = AgentAuditParams.builder()
            .offset(10)
            .limit(5)
            .build();

        TransparencyLogAudit result = client.getAgentTransparencyLogAudit(TEST_AGENT_ID, params);

        assertThat(result).isNotNull();
        assertThat(result.getRecords()).hasSize(1);
    }

    @Test
    @DisplayName("Should create client with default configuration")
    void shouldCreateClientWithDefaults() {
        TransparencyClient client = TransparencyClient.create();

        assertThat(client.getBaseUrl()).isEqualTo(TransparencyClient.DEFAULT_BASE_URL);
    }

    @Test
    @DisplayName("Should build client with custom timeouts")
    void shouldBuildClientWithCustomTimeouts(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(15))
            .build();

        assertThat(client).isNotNull();
        assertThat(client.getBaseUrl()).isEqualTo(baseUrl);
    }

    @Test
    @DisplayName("Should retrieve agent audit without params")
    void shouldRetrieveAgentAuditWithoutParams(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/audit"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(auditResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLogAudit result = client.getAgentTransparencyLogAudit(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.getRecords()).hasSize(1);
    }

    @Test
    @DisplayName("Should retrieve checkpoint history without params")
    void shouldRetrieveCheckpointHistoryWithoutParams(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/checkpoint/history"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(checkpointHistoryResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        CheckpointHistoryResponse result = client.getCheckpointHistory();

        assertThat(result).isNotNull();
        assertThat(result.getCheckpoints()).hasSize(1);
    }

    @Test
    @DisplayName("Should retrieve checkpoint history with params")
    void shouldRetrieveCheckpointHistoryWithParams(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Order is limit, offset per the implementation
        stubFor(get(urlEqualTo("/v1/log/checkpoint/history?limit=10&offset=5"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(checkpointHistoryResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        CheckpointHistoryParams params = CheckpointHistoryParams.builder()
            .offset(5)
            .limit(10)
            .build();

        CheckpointHistoryResponse result = client.getCheckpointHistory(params);

        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("Should retrieve log schema")
    void shouldRetrieveLogSchema(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/schema/V1"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"type\": \"object\", \"properties\": {}}")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        Map<String, Object> result = client.getLogSchema("V1");

        assertThat(result).isNotNull();
        assertThat(result).containsKey("type");
    }

    @Test
    @DisplayName("Should get transparency log asynchronously")
    void shouldGetTransparencyLogAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(v1TransparencyLogResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLog result = client.getAgentTransparencyLogAsync(TEST_AGENT_ID).get();

        assertThat(result).isNotNull();
        assertThat(result.isV1()).isTrue();
    }

    @Test
    @DisplayName("Should get audit log asynchronously")
    void shouldGetAuditLogAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/audit"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(auditResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLogAudit result = client.getAgentTransparencyLogAuditAsync(TEST_AGENT_ID, null).get();

        assertThat(result).isNotNull();
        assertThat(result.getRecords()).hasSize(1);
    }

    @Test
    @DisplayName("Should get checkpoint asynchronously")
    void shouldGetCheckpointAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/checkpoint"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(checkpointResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        CheckpointResponse result = client.getCheckpointAsync().get();

        assertThat(result).isNotNull();
        assertThat(result.getRootHash()).isEqualTo("abc123");
    }

    @Test
    @DisplayName("Should get checkpoint history asynchronously")
    void shouldGetCheckpointHistoryAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/checkpoint/history"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(checkpointHistoryResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        CheckpointHistoryResponse result = client.getCheckpointHistoryAsync(null).get();

        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("Should throw AnsServerException for 500 error")
    void shouldThrowServerExceptionFor500Error(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(500)
                .withHeader("X-Request-Id", "req-123")
                .withBody("{\"message\": \"Internal server error\"}")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getAgentTransparencyLog(TEST_AGENT_ID))
            .isInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should throw AnsServerException for unexpected 4xx error")
    void shouldThrowServerExceptionForUnexpected4xxError(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(403)
                .withBody("{\"message\": \"Forbidden\"}")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getAgentTransparencyLog(TEST_AGENT_ID))
            .isInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should throw AnsServerException for malformed response")
    void shouldThrowServerExceptionForMalformedResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/audit"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("not valid json")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getAgentTransparencyLogAudit(TEST_AGENT_ID))
            .isInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should throw AnsServerException for malformed checkpoint response")
    void shouldThrowServerExceptionForMalformedCheckpointResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/checkpoint"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("invalid json")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getCheckpoint())
            .isInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should throw AnsServerException for malformed checkpoint history response")
    void shouldThrowServerExceptionForMalformedCheckpointHistoryResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/checkpoint/history"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("invalid json")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getCheckpointHistory())
            .isInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should throw AnsServerException for malformed schema response")
    void shouldThrowServerExceptionForMalformedSchemaResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/v1/log/schema/V1"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("not a valid json object")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getLogSchema("V1"))
            .isInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should retrieve checkpoint history with all params")
    void shouldRetrieveCheckpointHistoryWithAllParams(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Build expected URL with all params
        stubFor(get(urlMatching("/v1/log/checkpoint/history\\?.*"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(checkpointHistoryResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        CheckpointHistoryParams params = CheckpointHistoryParams.builder()
            .offset(5)
            .limit(10)
            .fromSize(100)
            .toSize(500)
            .order("desc")
            .since(java.time.OffsetDateTime.now().minusDays(1))
            .build();

        CheckpointHistoryResponse result = client.getCheckpointHistory(params);

        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("Should handle V0 schema version from header")
    void shouldHandleV0SchemaVersionFromHeader(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Response without schemaVersion in body, relies on header
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Schema-Version", "V0")
                .withBody(v0TransparencyLogWithoutSchemaVersion())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLog result = client.getAgentTransparencyLog(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        assertThat(result.isV0()).isTrue();
    }

    @Test
    @DisplayName("Should default to V0 when no schema version present")
    void shouldDefaultToV0WhenNoSchemaVersionPresent(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        // Response without schemaVersion in body or header
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(v0TransparencyLogWithoutSchemaVersion())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        TransparencyLog result = client.getAgentTransparencyLog(TEST_AGENT_ID);

        assertThat(result).isNotNull();
        // Should default to V0
        assertThat(result.getSchemaVersion()).isEqualTo("V0");
    }

    @Test
    @DisplayName("Should retrieve root key from C2SP format")
    void shouldRetrieveRootKeyFromC2spFormat(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(rootKeyC2spSingleResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        Map<String, PublicKey> keys = client.getRootKeysAsync().join();

        assertThat(keys).isNotEmpty();
        assertThat(keys.values().iterator().next().getAlgorithm()).isEqualTo("EC");
    }

    @Test
    @DisplayName("Should retrieve multiple root keys from C2SP format")
    void shouldRetrieveMultipleRootKeysFromC2spFormat(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(rootKeyC2spMultipleResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        Map<String, PublicKey> keys = client.getRootKeysAsync().join();

        assertThat(keys).hasSize(2);
        keys.values().forEach(k -> assertThat(k.getAlgorithm()).isEqualTo("EC"));
    }

    @Test
    @DisplayName("Should retrieve root key asynchronously")
    void shouldRetrieveRootKeyAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(rootKeyC2spSingleResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        Map<String, PublicKey> keys = client.getRootKeysAsync().get();

        assertThat(keys).isNotEmpty();
        assertThat(keys.values().iterator().next().getAlgorithm()).isEqualTo("EC");
    }

    @Test
    @DisplayName("Should throw AnsServerException for root key 500 error")
    void shouldThrowServerExceptionForRootKeyError(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse()
                .withStatus(500)
                .withHeader("X-Request-Id", "req-123")
                .withBody("Internal error")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getRootKeysAsync().join())
            .hasCauseInstanceOf(com.godaddy.ans.sdk.exception.AnsServerException.class);
    }

    @Test
    @DisplayName("Should throw exception for invalid root key format")
    void shouldThrowExceptionForInvalidRootKeyFormat(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody("not a valid C2SP format line")));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThatThrownBy(() -> client.getRootKeysAsync().join())
            .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should retrieve receipt bytes")
    void shouldRetrieveReceiptBytes(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        byte[] expectedBytes = {0x01, 0x02, 0x03};

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/receipt"))
            .willReturn(aResponse()
                .withStatus(200)
                .withBody(expectedBytes)));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        byte[] result = client.getReceipt(TEST_AGENT_ID);
        assertThat(result).isEqualTo(expectedBytes);
    }

    @Test
    @DisplayName("Should retrieve status token bytes")
    void shouldRetrieveStatusTokenBytes(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        byte[] expectedBytes = {0x04, 0x05, 0x06};

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/status-token"))
            .willReturn(aResponse()
                .withStatus(200)
                .withBody(expectedBytes)));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        byte[] result = client.getStatusToken(TEST_AGENT_ID);
        assertThat(result).isEqualTo(expectedBytes);
    }

    @Test
    @DisplayName("Should retrieve receipt asynchronously")
    void shouldRetrieveReceiptAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        byte[] expectedBytes = {0x07, 0x08};

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/receipt"))
            .willReturn(aResponse()
                .withStatus(200)
                .withBody(expectedBytes)));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        byte[] result = client.getReceiptAsync(TEST_AGENT_ID).get();
        assertThat(result).isEqualTo(expectedBytes);
    }

    @Test
    @DisplayName("Should retrieve status token asynchronously")
    void shouldRetrieveStatusTokenAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        byte[] expectedBytes = {0x09, 0x0A};

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/status-token"))
            .willReturn(aResponse()
                .withStatus(200)
                .withBody(expectedBytes)));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        byte[] result = client.getStatusTokenAsync(TEST_AGENT_ID).get();
        assertThat(result).isEqualTo(expectedBytes);
    }

    @Test
    @DisplayName("Should build client with custom root key cache TTL")
    void shouldBuildClientWithCustomRootKeyCacheTtl(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .rootKeyCacheTtl(Duration.ofMinutes(30))
            .build();

        assertThat(client).isNotNull();
        assertThat(client.getBaseUrl()).isEqualTo(baseUrl);
    }

    @Test
    @DisplayName("Should invalidate root key cache")
    void shouldInvalidateRootKeyCache(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();

        stubFor(get(urlEqualTo("/root-keys"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "text/plain")
                .withBody(rootKeyC2spSingleResponse())));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        // First call fetches keys
        Map<String, PublicKey> keys1 = client.getRootKeysAsync().join();
        assertThat(keys1).isNotEmpty();

        // Invalidate cache - should not throw
        client.invalidateRootKeyCache();

        // Second call should fetch again (cache was invalidated)
        Map<String, PublicKey> keys2 = client.getRootKeysAsync().join();
        assertThat(keys2).isNotEmpty();
    }

    @Test
    @DisplayName("Should use default root key cache TTL of 24 hours")
    void shouldUseDefaultRootKeyCacheTtl() {
        assertThat(TransparencyClient.DEFAULT_ROOT_KEY_CACHE_TTL).isEqualTo(Duration.ofHours(24));
    }

    @Test
    @DisplayName("Should reject untrusted transparency log domain")
    void shouldRejectUntrustedDomain() {
        // malicious domain is not in our configured trusted domains
        assertThatThrownBy(() -> TransparencyClient.builder()
            .baseUrl("https://malicious-transparency-log.example.com")
            .build())
            .isInstanceOf(SecurityException.class)
            .hasMessageContaining("Untrusted transparency log domain")
            .hasMessageContaining("malicious-transparency-log.example.com");
    }

    @Test
    @DisplayName("Should accept trusted production domain")
    void shouldAcceptTrustedProductionDomain() {
        // These are in our configured trusted domains
        TransparencyClient prodClient = TransparencyClient.builder()
            .baseUrl("https://transparency.ans.godaddy.com")
            .build();
        assertThat(prodClient.getBaseUrl()).isEqualTo("https://transparency.ans.godaddy.com");

        TransparencyClient oteClient = TransparencyClient.builder()
            .baseUrl("https://transparency.ans.ote-godaddy.com")
            .build();
        assertThat(oteClient.getBaseUrl()).isEqualTo("https://transparency.ans.ote-godaddy.com");
    }

    // ==================== Test Data ====================

    private String v1TransparencyLogResponse() {
        return """
            {
              "status": "ACTIVE",
              "schemaVersion": "V1",
              "payload": {
                "logId": "log-123",
                "producer": {
                  "event": {
                    "ansId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                    "ansName": "ans://v1.0.0.agent.example.com",
                    "eventType": "AGENT_REGISTERED",
                    "agent": {
                      "host": "agent.example.com",
                      "name": "Example Agent",
                      "version": "v1.0.0"
                    },
                    "attestations": {
                      "domainValidation": "ACME-DNS-01",
                      "serverCert": {
                        "fingerprint": "SHA256:a1b2c3d4",
                        "type": "X509-DV-SERVER"
                      },
                      "identityCert": {
                        "fingerprint": "SHA256:e5f6g7h8",
                        "type": "X509-OV-CLIENT"
                      }
                    },
                    "issuedAt": "2025-09-24T21:03:47.055Z",
                    "expiresAt": "2026-09-24T21:03:47.055Z",
                    "raId": "ra.example.com",
                    "timestamp": "2025-09-24T21:03:47.055Z"
                  },
                  "keyId": "key-1",
                  "signature": "sig123"
                }
              },
              "signature": "eyJhbGci..."
            }
            """;
    }

    private String v0TransparencyLogResponse() {
        return """
            {
              "status": "ACTIVE",
              "schemaVersion": "V0",
              "payload": {
                "logId": "log-v0-123",
                "producer": {
                  "event": {
                    "agentFqdn": "agent.example.com",
                    "agentId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                    "ansName": "ans://v1.0.0.agent.example.com",
                    "eventType": "AGENT_ACTIVE",
                    "protocol": "https",
                    "raBadge": {
                      "attestations": {
                        "serverCertFingerprint": "SHA256:server123",
                        "clientCertFingerprint": "SHA256:client456",
                        "domainValidation": "ACME-DNS-01"
                      },
                      "badgeUrlStatus": "ACTIVE",
                      "issuedAt": "2025-09-24T21:03:47.055Z",
                      "raId": "ra.example.com"
                    },
                    "timestamp": "2025-09-24T21:03:47.055Z"
                  },
                  "keyId": "key-1",
                  "signature": "sig456"
                }
              }
            }
            """;
    }

    private String checkpointResponse() {
        return """
            {
              "logSize": 1000,
              "treeHeight": 10,
              "rootHash": "abc123",
              "originName": "transparency.ans.godaddy.com",
              "checkpointFormat": "sigsum",
              "publicKeyPem": "-----BEGIN PUBLIC KEY-----..."
            }
            """;
    }

    private String auditResponse() {
        return """
            {
              "records": [
                {
                  "status": "ACTIVE",
                  "schemaVersion": "V1",
                  "payload": {
                    "logId": "log-123",
                    "producer": {
                      "event": {
                        "ansId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                        "ansName": "ans://v1.0.0.agent.example.com",
                        "eventType": "AGENT_REGISTERED",
                        "agent": {
                          "host": "agent.example.com",
                          "version": "v1.0.0"
                        },
                        "attestations": {},
                        "issuedAt": "2025-09-24T21:03:47.055Z",
                        "timestamp": "2025-09-24T21:03:47.055Z"
                      },
                      "keyId": "key-1",
                      "signature": "sig"
                    }
                  }
                }
              ]
            }
            """;
    }

    private String checkpointHistoryResponse() {
        return """
            {
              "checkpoints": [
                {
                  "logSize": 500,
                  "treeHeight": 9,
                  "rootHash": "def456",
                  "timestamp": "2025-01-15T10:00:00Z"
                }
              ],
              "pagination": {
                "offset": 0,
                "limit": 10,
                "total": 1
              }
            }
            """;
    }

    private String v0TransparencyLogWithoutSchemaVersion() {
        return """
            {
              "status": "ACTIVE",
              "payload": {
                "logId": "log-v0-123",
                "producer": {
                  "event": {
                    "agentFqdn": "agent.example.com",
                    "agentId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                    "ansName": "ans://v1.0.0.agent.example.com",
                    "eventType": "AGENT_ACTIVE",
                    "protocol": "https",
                    "raBadge": {
                      "attestations": {
                        "serverCertFingerprint": "SHA256:server123",
                        "clientCertFingerprint": "SHA256:client456",
                        "domainValidation": "ACME-DNS-01"
                      },
                      "badgeUrlStatus": "ACTIVE",
                      "issuedAt": "2025-09-24T21:03:47.055Z",
                      "raId": "ra.example.com"
                    },
                    "timestamp": "2025-09-24T21:03:47.055Z"
                  },
                  "keyId": "key-1",
                  "signature": "sig456"
                }
              }
            }
            """;
    }

    // Valid EC P-256 public key for testing (SPKI-DER, base64 encoded)
    private static final String TEST_EC_PUBLIC_KEY =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEveuRZW0vWcVjh4enr9tA7VAKPFmL"
        + "OZs1S99lGDqRhAQBEdetB290Det8rO1ojnHEA8PX4Yojb0oomwA2krO5Ag==";

    // Second test key (different point on P-256 curve)
    private static final String TEST_EC_PUBLIC_KEY_2 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb3cL8bLB0m5Dz7NiJj3xz0oPp4at"
        + "Hj8bTqJf4d3nVkPR5eK8jFrLhCPQgKcZvWpJhH9q0vwPiT3v5RCKnGdDgA==";

    /**
     * Returns a valid EC P-256 public key in C2SP note format.
     */
    private String rootKeyC2spSingleResponse() {
        return "transparency.ans.godaddy.com+abcd1234+" + TEST_EC_PUBLIC_KEY;
    }

    /**
     * Returns multiple valid EC P-256 public keys in C2SP note format.
     */
    private String rootKeyC2spMultipleResponse() {
        return "transparency.ans.godaddy.com+abcd1234+" + TEST_EC_PUBLIC_KEY + "\n"
            + "transparency.ans.godaddy.com+efgh5678+" + TEST_EC_PUBLIC_KEY_2;
    }
}