package com.godaddy.ans.sdk.transparency.verification;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.dns.RaBadgeLookupService;
import com.godaddy.ans.sdk.transparency.dns.RaBadgeRecord;
import com.godaddy.ans.sdk.transparency.model.AgentV1;
import com.godaddy.ans.sdk.transparency.model.AttestationsV1;
import com.godaddy.ans.sdk.transparency.model.CertificateInfo;
import com.godaddy.ans.sdk.transparency.model.CertType;
import com.godaddy.ans.sdk.transparency.model.EventV1;
import com.godaddy.ans.sdk.transparency.model.ProducerV1;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import com.godaddy.ans.sdk.transparency.model.TransparencyLogV1;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for version change handling scenarios.
 * Tests the badge selection logic when multiple versions exist.
 */
class VersionChangeHandlingTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID_V1 = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_AGENT_ID_V2 = "7cf3c8b0-2494-5f44-b056-956f45bf8637";
    private static final String TEST_ANS_NAME_V1 = "ans://v1.0.0.agent.example.com";
    private static final String TEST_ANS_NAME_V2 = "ans://v1.0.1.agent.example.com";
    private static final String TEST_FINGERPRINT_V1 =
            "SHA256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    private static final String TEST_FINGERPRINT_V2 =
            "SHA256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";

    @Mock
    private TransparencyClient transparencyClient;

    @Mock
    private RaBadgeLookupService raBadgeLookupService;

    @Mock
    private X509Certificate mockCertificate;

    private BadgeVerificationService verificationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        verificationService = BadgeVerificationService.builder()
            .transparencyClient(transparencyClient)
            .raBadgeLookupService(raBadgeLookupService)
            .build();
    }

    // ==================== Two ACTIVE versions ====================

    @Test
    @DisplayName("Should select correct badge when two ACTIVE versions exist")
    void shouldSelectCorrectBadgeWithTwoActiveVersions() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - client presents v1.0.0 identity cert
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME_V1));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT_V1);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT_V1, TEST_FINGERPRINT_V1))
                .thenReturn(true);

            // Two badges - v1.0.0 and v1.0.1 both ACTIVE
            RaBadgeRecord badgeV1 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V1);
            RaBadgeRecord badgeV2 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V2);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badgeV1, badgeV2));

            // Both registrations are ACTIVE
            TransparencyLog registrationV1 = createMockRegistration("ACTIVE", TEST_FINGERPRINT_V1, TEST_ANS_NAME_V1);
            TransparencyLog registrationV2 = createMockRegistration("ACTIVE", TEST_FINGERPRINT_V2, TEST_ANS_NAME_V2);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V1)).thenReturn(registrationV1);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V2)).thenReturn(registrationV2);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should select v1.0.0 badge and pass
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedAnsName()).isEqualTo(TEST_ANS_NAME_V1);
            assertThat(result.getExpectedIdentityCertFingerprint()).isEqualTo(TEST_FINGERPRINT_V1);

            // Should only fetch the v1.0.0 registration (version filtering optimization)
            verify(transparencyClient).getAgentTransparencyLog(TEST_AGENT_ID_V1);
        }
    }

    // ==================== Old version DEPRECATED ====================

    @Test
    @DisplayName("Should pass with warning when old version is DEPRECATED")
    void shouldPassWithWarningWhenOldVersionDeprecated() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - client presents v1.0.0 identity cert (old version)
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME_V1));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT_V1);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT_V1, TEST_FINGERPRINT_V1))
                .thenReturn(true);

            // Two badges - v1.0.0 DEPRECATED, v1.0.1 ACTIVE
            RaBadgeRecord badgeV1 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/"
                        + TEST_AGENT_ID_V1);
            RaBadgeRecord badgeV2 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/"
                        + TEST_AGENT_ID_V2);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badgeV1, badgeV2));

            // v1.0.0 is DEPRECATED, v1.0.1 is ACTIVE
            TransparencyLog registrationV1 = createMockRegistration("DEPRECATED", TEST_FINGERPRINT_V1,
                    TEST_ANS_NAME_V1);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V1)).thenReturn(registrationV1);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should pass with DEPRECATED_OK status
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
            assertThat(result.getWarningMessage()).contains("deprecated");
        }
    }

    // ==================== No matching version in DNS ====================

    @Test
    @DisplayName("Should reject when no matching version in DNS")
    void shouldRejectWhenNoMatchingVersionInDns() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - client presents v1.0.0 cert, but DNS only has v1.0.1
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME_V1)); // v1.0.0
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT_V1);
            // Fingerprint doesn't match v1.0.1's fingerprint
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT_V1, TEST_FINGERPRINT_V2))
                .thenReturn(false);

            // Only v1.0.1 badge exists in DNS
            RaBadgeRecord badgeV2 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V2);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badgeV2));

            // v1.0.1 registration doesn't match the cert
            TransparencyLog registrationV2 = createMockRegistration("ACTIVE", TEST_FINGERPRINT_V2, TEST_ANS_NAME_V2);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V2)).thenReturn(registrationV2);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with fingerprint mismatch (no matching badge)
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    // ==================== Server verification without version ====================

    @Test
    @DisplayName("Should prefer ACTIVE badge when server cert has no version")
    void shouldPreferActiveBadgeWhenServerCertHasNoVersion() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - client presents cert without version (no URI SAN)
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.empty()); // No version in cert
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT_V2);
            // Fingerprint matches v1.0.1's fingerprint
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT_V2, TEST_FINGERPRINT_V2))
                .thenReturn(true);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT_V2, TEST_FINGERPRINT_V1))
                .thenReturn(false);

            // Two badges - v1.0.0 DEPRECATED, v1.0.1 ACTIVE
            RaBadgeRecord badgeV1 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V1);
            RaBadgeRecord badgeV2 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V2);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badgeV1, badgeV2));

            // v1.0.0 is DEPRECATED, v1.0.1 is ACTIVE
            TransparencyLog registrationV1 = createMockRegistrationNoAnsName("DEPRECATED", TEST_FINGERPRINT_V1);
            TransparencyLog registrationV2 = createMockRegistrationNoAnsName("ACTIVE", TEST_FINGERPRINT_V2);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V1)).thenReturn(registrationV1);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V2)).thenReturn(registrationV2);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should prefer ACTIVE badge (v1.0.1)
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        }
    }

    // ==================== Partial fetch failure ====================

    @Test
    @DisplayName("Should pass if successful badge matches despite partial failure")
    void shouldPassIfSuccessfulBadgeMatchesDespitePartialFailure() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - client presents v1.0.0 identity cert
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME_V1));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT_V1);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT_V1, TEST_FINGERPRINT_V1))
                .thenReturn(true);

            // Two badges - v1.0.0 and v1.0.1
            RaBadgeRecord badgeV1 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V1);
            RaBadgeRecord badgeV2 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V2);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badgeV2, badgeV1));

            // v1.0.1 fetch fails (5xx), but v1.0.0 succeeds
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V2))
                .thenThrow(new RuntimeException("Service unavailable"));
            TransparencyLog registrationV1 = createMockRegistration("ACTIVE", TEST_FINGERPRINT_V1, TEST_ANS_NAME_V1);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V1)).thenReturn(registrationV1);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should pass because the matching badge (v1.0.0) succeeded
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedAnsName()).isEqualTo(TEST_ANS_NAME_V1);
        }
    }

    @Test
    @DisplayName("Should apply failure policy when all badge fetches fail")
    void shouldApplyFailurePolicyWhenAllBadgeFetchesFail() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - client presents cert
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME_V1));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT_V1);

            // Two badges exist
            RaBadgeRecord badgeV1 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V1);
            RaBadgeRecord badgeV2 = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID_V2);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badgeV1, badgeV2));

            // Both fetch attempts fail
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V1))
                .thenThrow(new RuntimeException("Service unavailable"));
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID_V2))
                .thenThrow(new RuntimeException("Service unavailable"));

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with lookup failure
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        }
    }

    // ==================== Helper Methods ====================

    private TransparencyLog createMockRegistration(String status, String fingerprint, String ansName) {
        CertificateInfo serverCert = new CertificateInfo();
        serverCert.setFingerprint(fingerprint);
        serverCert.setType(CertType.X509_DV_SERVER);

        CertificateInfo identityCert = new CertificateInfo();
        identityCert.setFingerprint(fingerprint);
        identityCert.setType(CertType.X509_OV_CLIENT);

        AttestationsV1 attestations = new AttestationsV1();
        attestations.setServerCert(serverCert);
        attestations.setIdentityCert(identityCert);

        AgentV1 agent = new AgentV1();
        agent.setHost(TEST_HOSTNAME);
        agent.setName("Test Agent");
        agent.setVersion(ansName.contains("v1.0.0") ? "v1.0.0" : "v1.0.1");

        EventV1 event = new EventV1();
        event.setAnsName(ansName);
        event.setAgent(agent);
        event.setAttestations(attestations);

        ProducerV1 producer = new ProducerV1();
        producer.setEvent(event);

        TransparencyLogV1 v1Payload = new TransparencyLogV1();
        v1Payload.setLogId("log-123");
        v1Payload.setProducer(producer);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("V1");
        log.setParsedPayload(v1Payload);

        return log;
    }

    private TransparencyLog createMockRegistrationNoAnsName(String status, String fingerprint) {
        CertificateInfo serverCert = new CertificateInfo();
        serverCert.setFingerprint(fingerprint);
        serverCert.setType(CertType.X509_DV_SERVER);

        CertificateInfo identityCert = new CertificateInfo();
        identityCert.setFingerprint(fingerprint);
        identityCert.setType(CertType.X509_OV_CLIENT);

        AttestationsV1 attestations = new AttestationsV1();
        attestations.setServerCert(serverCert);
        attestations.setIdentityCert(identityCert);

        AgentV1 agent = new AgentV1();
        agent.setHost(TEST_HOSTNAME);
        agent.setName("Test Agent");
        agent.setVersion("v1.0.0");

        EventV1 event = new EventV1();
        event.setAnsName(null); // No ANS name
        event.setAgent(agent);
        event.setAttestations(attestations);

        ProducerV1 producer = new ProducerV1();
        producer.setEvent(event);

        TransparencyLogV1 v1Payload = new TransparencyLogV1();
        v1Payload.setLogId("log-123");
        v1Payload.setProducer(producer);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("V1");
        log.setParsedPayload(v1Payload);

        return log;
    }
}
