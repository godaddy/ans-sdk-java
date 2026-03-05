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
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for client certificate verification via mTLS.
 * Tests the {@link BadgeVerificationService#verifyClient(X509Certificate)} method.
 */
class ClientVerificationTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_ANS_NAME = "ans://v1.0.0.agent.example.com";
    private static final String TEST_FINGERPRINT =
            "SHA256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

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

    // ==================== All Fields Match, ACTIVE ====================

    @Test
    @DisplayName("Should pass when all fields match with ACTIVE status")
    void shouldPassWhenAllFieldsMatchWithActiveStatus() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate utilities
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with matching fingerprint
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedIdentityCertFingerprint()).isEqualTo(TEST_FINGERPRINT);
            assertThat(result.getExpectedAnsName()).isEqualTo(TEST_ANS_NAME);
            assertThat(result.getExpectedAgentHost()).isEqualTo(TEST_HOSTNAME);
        }
    }

    // ==================== No URI SAN in Cert ====================

    @Test
    @DisplayName("Should verify when cert has no URI SAN (ANS name comparison skipped)")
    void shouldVerifyWhenCertHasNoUriSan() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate with NO URI SAN
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.empty()); // No URI SAN
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with no ANS name check needed
            TransparencyLog registration = createMockRegistrationNoAnsName("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should verify based on fingerprint and hostname
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        }
    }

    // ==================== DNS SAN Mismatch ====================

    @Test
    @DisplayName("Should reject when CN (hostname) does not match agent.host")
    void shouldRejectWhenCnMismatchesAgentHost() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate with DIFFERENT hostname
            String differentHostname = "different-agent.example.com";
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(differentHostname));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(differentHostname);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup for the cert's hostname
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(differentHostname)).thenReturn(List.of(badge));

            // Mock registration with DIFFERENT agent.host
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            // agent.host in registration is TEST_HOSTNAME but cert has different-agent.example.com
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with hostname mismatch
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.HOSTNAME_MISMATCH);
        }
    }

    // ==================== URI SAN Mismatch ====================

    @Test
    @DisplayName("Should reject when URI SAN does not match ansName")
    void shouldRejectWhenUriSanMismatchesAnsName() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate with DIFFERENT ANS name
            String differentAnsName = "ans://v2.0.0.agent.example.com";
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(differentAnsName)); // Different version
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with DIFFERENT ansName
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            // ansName in registration is TEST_ANS_NAME (v1.0.0) but cert has v2.0.0
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with ANS name mismatch
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.ANS_NAME_MISMATCH);
        }
    }

    // ==================== Fingerprint Mismatch ====================

    @Test
    @DisplayName("Should reject when fingerprint does not match identityCert")
    void shouldRejectWhenFingerprintMismatchesIdentityCert() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            String differentFingerprint = "SHA256:different1234567890abcdef1234567890abcdef1234567890abcdef12345678";
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(differentFingerprint);
            // Fingerprints DON'T match
            certUtils.when(() -> CertificateUtils.fingerprintMatches(differentFingerprint, TEST_FINGERPRINT))
                .thenReturn(false);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with DIFFERENT fingerprint
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with fingerprint mismatch
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    // ==================== DEPRECATED Status ====================

    @Test
    @DisplayName("Should pass with warning when all fields match but status is DEPRECATED")
    void shouldPassWithWarningWhenDeprecatedStatus() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with DEPRECATED status
            TransparencyLog registration = createMockRegistration("DEPRECATED", TEST_FINGERPRINT);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should pass with DEPRECATED_OK status
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
            assertThat(result.getWarningMessage()).contains("deprecated");
        }
    }

    // ==================== EXPIRED Status ====================

    @Test
    @DisplayName("Should return REGISTRATION_INVALID when status is EXPIRED")
    void shouldReturnRegistrationInvalidWhenExpiredStatus() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with EXPIRED status (even though fingerprint matches)
            TransparencyLog registration = createMockRegistration("EXPIRED", TEST_FINGERPRINT);
            when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - registration matched but status is invalid
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
            assertThat(result.getWarningMessage()).contains("EXPIRED");
        }
    }

    // ==================== No Badge Record ====================

    @Test
    @DisplayName("Should return NOT_ANS_AGENT when no ra-badge record exists")
    void shouldReturnNotAnsAgentWhenNoBadgeRecord() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));

            // Mock no badge records found
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of());

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.NOT_ANS_AGENT);
        }
    }

    // ==================== 4.10 No FQDN in Certificate ====================

    @Test
    @DisplayName("4.10 Should return LOOKUP_FAILED when certificate has no FQDN")
    void shouldReturnLookupFailedWhenNoFqdn() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - certificate has no FQDN (no DNS SAN or CN)
            certUtils.when(() -> CertificateUtils.extractFqdn(mockCertificate))
                .thenReturn(Optional.empty());

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
            assertThat(result.getWarningMessage()).contains("FQDN");
        }
    }

    // ==================== Helper Methods ====================

    private TransparencyLog createMockRegistration(String status, String fingerprint) {
        return createMockRegistration(status, fingerprint, TEST_ANS_NAME);
    }

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
        agent.setVersion("v1.0.0");

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
