package com.godaddy.ans.sdk.registration;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.godaddy.ans.sdk.auth.ApiKeyCredentialsProvider;
import com.godaddy.ans.sdk.config.AnsConfiguration;
import com.godaddy.ans.sdk.config.Environment;
import com.godaddy.ans.sdk.exception.AnsAuthenticationException;
import com.godaddy.ans.sdk.exception.AnsNotFoundException;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.exception.AnsValidationException;
import com.godaddy.ans.sdk.model.generated.CertificateResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for CertificateService certificate retrieval methods.
 */
@WireMockTest
class CertificateServiceTest {

    private static final String TEST_AGENT_ID = "test-agent-123";
    private static final String API_KEY = "test-api-key";
    private static final String API_SECRET = "test-api-secret";

    private CertificateService createCertificateService(WireMockRuntimeInfo wmRuntimeInfo) {
        AnsConfiguration config = AnsConfiguration.builder()
            .environment(Environment.OTE)
            .baseUrl(wmRuntimeInfo.getHttpBaseUrl())
            .credentialsProvider(new ApiKeyCredentialsProvider(API_KEY, API_SECRET))
            .build();
        return new CertificateService(config);
    }

    // ==================== getServerCertificates Tests ====================

    @Test
    @DisplayName("getServerCertificates should return list of certificates on success")
    void getServerCertificatesShouldReturnListOnSuccess(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        String responseJson = """
            [
                {
                    "csrId": "550e8400-e29b-41d4-a716-446655440001",
                    "certificateSubject": "CN=test-agent.example.com",
                    "certificateIssuer": "CN=ANS CA",
                    "certificateSerialNumber": "1234567890",
                    "certificateValidFrom": "2024-01-01T00:00:00Z",
                    "certificateValidTo": "2025-01-01T00:00:00Z",
                    "certificatePEM": "-----BEGIN CERTIFICATE-----\\nMIIB...\\n-----END CERTIFICATE-----",
                    "chainPEM": "-----BEGIN CERTIFICATE-----\\nMIIC...\\n-----END CERTIFICATE-----",
                    "certificatePublicKeyAlgorithm": "EC",
                    "certificateSignatureAlgorithm": "SHA256withECDSA"
                }
            ]
            """;

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(responseJson)));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When
        List<CertificateResponse> certificates = certificateService.getServerCertificates(TEST_AGENT_ID);

        // Then
        assertThat(certificates).hasSize(1);
        CertificateResponse cert = certificates.get(0);
        assertThat(cert.getCertificateSubject()).isEqualTo("CN=test-agent.example.com");
        assertThat(cert.getCertificateIssuer()).isEqualTo("CN=ANS CA");
        assertThat(cert.getCertificatePEM()).startsWith("-----BEGIN CERTIFICATE-----");

        verify(getRequestedFor(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .withHeader("Authorization", containing("sso-key")));
    }

    @Test
    @DisplayName("getServerCertificates should return empty list when no certificates exist")
    void getServerCertificatesShouldReturnEmptyListWhenNoCertificates(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("[]")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When
        List<CertificateResponse> certificates = certificateService.getServerCertificates(TEST_AGENT_ID);

        // Then
        assertThat(certificates).isEmpty();
    }

    @Test
    @DisplayName("getServerCertificates should throw AnsNotFoundException when agent not found")
    void getServerCertificatesShouldThrowNotFoundWhenAgentNotFound(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Agent not found\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsNotFoundException.class);
    }

    @Test
    @DisplayName("getServerCertificates should return multiple certificates")
    void getServerCertificatesShouldReturnMultipleCertificates(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        String responseJson = """
            [
                {
                    "csrId": "550e8400-e29b-41d4-a716-446655440001",
                    "certificateSubject": "CN=test-agent.example.com",
                    "certificateValidFrom": "2024-01-01T00:00:00Z",
                    "certificateValidTo": "2025-01-01T00:00:00Z",
                    "certificatePEM": "-----BEGIN CERTIFICATE-----\\nCERT1\\n-----END CERTIFICATE-----"
                },
                {
                    "csrId": "550e8400-e29b-41d4-a716-446655440002",
                    "certificateSubject": "CN=test-agent.example.com",
                    "certificateValidFrom": "2023-01-01T00:00:00Z",
                    "certificateValidTo": "2024-01-01T00:00:00Z",
                    "certificatePEM": "-----BEGIN CERTIFICATE-----\\nCERT2\\n-----END CERTIFICATE-----"
                }
            ]
            """;

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(responseJson)));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When
        List<CertificateResponse> certificates = certificateService.getServerCertificates(TEST_AGENT_ID);

        // Then
        assertThat(certificates).hasSize(2);
    }

    // ==================== getIdentityCertificates Tests ====================

    @Test
    @DisplayName("getIdentityCertificates should return list of certificates on success")
    void getIdentityCertificatesShouldReturnListOnSuccess(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        String responseJson = """
            [
                {
                    "csrId": "550e8400-e29b-41d4-a716-446655440003",
                    "certificateSubject": "CN=test-agent.example.com",
                    "certificateIssuer": "CN=ANS Identity CA",
                    "certificateSerialNumber": "9876543210",
                    "certificateValidFrom": "2024-01-01T00:00:00Z",
                    "certificateValidTo": "2025-01-01T00:00:00Z",
                    "certificatePEM": "-----BEGIN CERTIFICATE-----\\nIDENTITY...\\n-----END CERTIFICATE-----",
                    "certificatePublicKeyAlgorithm": "EC",
                    "certificateSignatureAlgorithm": "SHA256withECDSA"
                }
            ]
            """;

        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(responseJson)));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When
        List<CertificateResponse> certificates = certificateService.getIdentityCertificates(TEST_AGENT_ID);

        // Then
        assertThat(certificates).hasSize(1);
        CertificateResponse cert = certificates.get(0);
        assertThat(cert.getCertificateSubject()).isEqualTo("CN=test-agent.example.com");
        assertThat(cert.getCertificateIssuer()).isEqualTo("CN=ANS Identity CA");

        verify(getRequestedFor(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .withHeader("Authorization", containing("sso-key")));
    }

    @Test
    @DisplayName("getIdentityCertificates should return empty list when no certificates exist")
    void getIdentityCertificatesShouldReturnEmptyListWhenNoCertificates(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("[]")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When
        List<CertificateResponse> certificates = certificateService.getIdentityCertificates(TEST_AGENT_ID);

        // Then
        assertThat(certificates).isEmpty();
    }

    @Test
    @DisplayName("getIdentityCertificates should throw AnsNotFoundException when agent not found")
    void getIdentityCertificatesShouldThrowNotFoundWhenAgentNotFound(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Agent not found\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getIdentityCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsNotFoundException.class);
    }

    // ==================== Validation Tests ====================

    @Test
    @DisplayName("getServerCertificates should reject null agentId")
    void getServerCertificatesShouldRejectNullAgentId(WireMockRuntimeInfo wmRuntimeInfo) {
        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        assertThatThrownBy(() -> certificateService.getServerCertificates(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("agentId");
    }

    @Test
    @DisplayName("getIdentityCertificates should reject null agentId")
    void getIdentityCertificatesShouldRejectNullAgentId(WireMockRuntimeInfo wmRuntimeInfo) {
        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        assertThatThrownBy(() -> certificateService.getIdentityCertificates(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("agentId");
    }

    @Test
    @DisplayName("getServerCertificates should reject blank agentId")
    void getServerCertificatesShouldRejectBlankAgentId(WireMockRuntimeInfo wmRuntimeInfo) {
        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        assertThatThrownBy(() -> certificateService.getServerCertificates(""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("agentId");
    }

    @Test
    @DisplayName("getIdentityCertificates should reject blank agentId")
    void getIdentityCertificatesShouldRejectBlankAgentId(WireMockRuntimeInfo wmRuntimeInfo) {
        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        assertThatThrownBy(() -> certificateService.getIdentityCertificates(""))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("agentId");
    }

    // ==================== Authentication Error Tests ====================

    @Test
    @DisplayName("getServerCertificates should throw AnsAuthenticationException on 401")
    void getServerCertificatesShouldThrowAuthExceptionOn401(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Request-Id", "req-123")
                .withBody("{\"message\": \"Invalid API key\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Authentication failed");
    }

    @Test
    @DisplayName("getServerCertificates should throw AnsAuthenticationException on 403")
    void getServerCertificatesShouldThrowAuthExceptionOn403(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(403)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Access denied\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsAuthenticationException.class)
            .hasMessageContaining("Authentication failed");
    }

    @Test
    @DisplayName("getIdentityCertificates should throw AnsAuthenticationException on 401")
    void getIdentityCertificatesShouldThrowAuthExceptionOn401(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .willReturn(aResponse()
                .withStatus(401)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Unauthorized\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getIdentityCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsAuthenticationException.class);
    }

    // ==================== Validation Error Tests ====================

    @Test
    @DisplayName("getServerCertificates should throw AnsValidationException on 422")
    void getServerCertificatesShouldThrowValidationExceptionOn422(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(422)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Invalid agent ID format\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsValidationException.class)
            .hasMessageContaining("Validation error");
    }

    @Test
    @DisplayName("getIdentityCertificates should throw AnsValidationException on 422")
    void getIdentityCertificatesShouldThrowValidationExceptionOn422(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .willReturn(aResponse()
                .withStatus(422)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Validation failed\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getIdentityCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsValidationException.class);
    }

    // ==================== Server Error Tests ====================

    @Test
    @DisplayName("getServerCertificates should throw AnsServerException on 500")
    void getServerCertificatesShouldThrowServerExceptionOn500(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Request-Id", "req-456")
                .withBody("{\"message\": \"Internal server error\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Server error");
    }

    @Test
    @DisplayName("getServerCertificates should throw AnsServerException on 502")
    void getServerCertificatesShouldThrowServerExceptionOn502(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(502)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Bad gateway\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsServerException.class);
    }

    @Test
    @DisplayName("getServerCertificates should throw AnsServerException on 503")
    void getServerCertificatesShouldThrowServerExceptionOn503(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(503)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Service unavailable\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsServerException.class);
    }

    @Test
    @DisplayName("getIdentityCertificates should throw AnsServerException on 500")
    void getIdentityCertificatesShouldThrowServerExceptionOn500(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/identity"))
            .willReturn(aResponse()
                .withStatus(500)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"Internal server error\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getIdentityCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsServerException.class);
    }

    @Test
    @DisplayName("getServerCertificates should throw AnsServerException on unexpected 4xx error")
    void getServerCertificatesShouldThrowServerExceptionOnUnexpected4xx(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given - 418 I'm a teapot (unexpected client error)
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(418)
                .withHeader("Content-Type", "application/json")
                .withBody("{\"message\": \"I'm a teapot\"}")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Unexpected error (418)");
    }

    @Test
    @DisplayName("getServerCertificates should throw AnsServerException on malformed JSON response")
    void getServerCertificatesShouldThrowServerExceptionOnMalformedJson(WireMockRuntimeInfo wmRuntimeInfo) {
        // Given
        stubFor(get(urlEqualTo("/v1/agents/" + TEST_AGENT_ID + "/certificates/server"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("not valid json")));

        CertificateService certificateService = createCertificateService(wmRuntimeInfo);

        // When/Then
        assertThatThrownBy(() -> certificateService.getServerCertificates(TEST_AGENT_ID))
            .isInstanceOf(AnsServerException.class)
            .hasMessageContaining("Failed to parse");
    }
}
