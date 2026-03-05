package com.godaddy.ans.sdk.transparency.verification;

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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import com.godaddy.ans.sdk.crypto.CertificateUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BadgeVerificationServiceTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_FINGERPRINT = "SHA256:a1b2c3d4e5f6g7h8";
    private static final String TEST_ANS_NAME = "ans://v1.0.0.agent.example.com";

    @Mock
    private TransparencyClient transparencyClient;

    @Mock
    private RaBadgeLookupService raBadgeLookupService;

    private BadgeVerificationService verificationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        verificationService = BadgeVerificationService.builder()
            .transparencyClient(transparencyClient)
            .raBadgeLookupService(raBadgeLookupService)
            .build();
    }

    @Test
    @DisplayName("Should verify server and return expectedAgentHost")
    void shouldVerifyServerAndReturnExpectedAgentHost() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        TransparencyLog registration = createMockRegistration("ACTIVE");
        when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprint()).isEqualTo(TEST_FINGERPRINT);
        assertThat(result.getExpectedAgentHost()).isEqualTo(TEST_HOSTNAME);
    }

    @Test
    @DisplayName("Should return DEPRECATED_OK status for deprecated registration")
    void shouldReturnDeprecatedOkForDeprecatedRegistration() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        TransparencyLog registration = createMockRegistration("DEPRECATED");
        when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
        assertThat(result.getExpectedAgentHost()).isEqualTo(TEST_HOSTNAME);
        assertThat(result.getWarningMessage()).contains("deprecated");
    }

    @Test
    @DisplayName("Should return NOT_ANS_AGENT when no ra-badge record exists")
    void shouldReturnNotAnsAgentWhenNoBadgeRecord() {
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of());

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.NOT_ANS_AGENT);
    }

    @Test
    @DisplayName("Should return REGISTRATION_INVALID for revoked registration")
    void shouldReturnRegistrationInvalidForRevokedRegistration() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        TransparencyLog registration = createMockRegistration("REVOKED");
        when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
    }

    @Test
    @DisplayName("Should return LOOKUP_FAILED when transparency client throws exception")
    void shouldReturnLookupFailedOnException() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
        when(transparencyClient.getAgentTransparencyLog(anyString()))
            .thenThrow(new RuntimeException("Network error"));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        assertThat(result.getWarningMessage()).contains("Network error");
    }

    // ==================== WARNING Status ====================

    @Test
    @DisplayName("Should verify server with WARNING status and proceed")
    void shouldVerifyServerWithWarningStatus() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        TransparencyLog registration = createMockRegistration("WARNING");
        when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprint()).isEqualTo(TEST_FINGERPRINT);
        assertThat(result.getExpectedAgentHost()).isEqualTo(TEST_HOSTNAME);
        assertThat(result.getWarningMessage()).contains("WARNING");
    }

    // ==================== EXPIRED Status ====================

    @Test
    @DisplayName("Should reject server with EXPIRED status")
    void shouldRejectServerWithExpiredStatus() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        TransparencyLog registration = createMockRegistration("EXPIRED");
        when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
        assertThat(result.getWarningMessage()).contains("EXPIRED");
    }

    // ==================== TL Unreachable ====================

    @Test
    @DisplayName("Should apply failure policy when TL returns connection timeout")
    void shouldApplyFailurePolicyWhenTlConnectionTimeout() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
        when(transparencyClient.getAgentTransparencyLog(anyString()))
            .thenThrow(new RuntimeException("Connection timeout"));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        assertThat(result.getWarningMessage()).contains("timeout");
    }

    @Test
    @DisplayName("Should apply failure policy when TL returns 5xx error")
    void shouldApplyFailurePolicyWhenTlReturns5xx() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
        when(transparencyClient.getAgentTransparencyLog(anyString()))
            .thenThrow(new RuntimeException("HTTP 503 Service Unavailable"));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        assertThat(result.getWarningMessage()).contains("503");
    }

    // ==================== Badge URL Returns 404 ====================

    @Test
    @DisplayName("Should apply failure policy when badge URL returns 404")
    void shouldApplyFailurePolicyWhenBadgeUrlReturns404() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
        when(transparencyClient.getAgentTransparencyLog(anyString()))
            .thenThrow(new RuntimeException("HTTP 404 Not Found"));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        assertThat(result.getWarningMessage()).contains("404");
    }

    // ==================== Edge Cases ====================

    @Test
    @DisplayName("Should return LOOKUP_FAILED when badge URL has invalid path format")
    void shouldReturnLookupFailedWhenBadgeUrlHasInvalidPath() {
        // Badge with invalid URL path (fails URL validation before agent ID check)
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/invalid-path");
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        assertThat(result.getWarningMessage()).contains("badge URL");
    }

    @Test
    @DisplayName("Should return REGISTRATION_INVALID for unknown status")
    void shouldReturnRegistrationInvalidForUnknownStatus() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

        TransparencyLog registration = createMockRegistration("UNKNOWN_STATUS");
        when(transparencyClient.getAgentTransparencyLog(TEST_AGENT_ID)).thenReturn(registration);

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
        assertThat(result.getWarningMessage()).contains("Unknown");
    }

    // ==================== Multiple Badge Server Verification Tests ====================

    @Nested
    @DisplayName("Multiple Badge Server Verification Tests")
    class MultipleBadgeServerVerificationTests {

        private static final String AGENT_ID_1 = "11111111-1111-1111-1111-111111111111";
        private static final String AGENT_ID_2 = "22222222-2222-2222-2222-222222222222";
        private static final String FINGERPRINT_1 = "SHA256:fingerprint1111";
        private static final String FINGERPRINT_2 = "SHA256:fingerprint2222";

        @Test
        @DisplayName("Should return all fingerprints from multiple ACTIVE registrations")
        void shouldReturnAllFingerprintsFromMultipleActiveRegistrations() {
            // Given - 2 badge records with different agent IDs
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            // Both registrations are ACTIVE with different fingerprints
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenReturn(createMockRegistrationWithFingerprint("ACTIVE", FINGERPRINT_1));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationWithFingerprint("ACTIVE", FINGERPRINT_2));

            // When
            ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

            // Then - should return VERIFIED with both fingerprints
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedServerCertFingerprints())
                .containsExactlyInAnyOrder(FINGERPRINT_1, FINGERPRINT_2);
        }

        @Test
        @DisplayName("Should return fingerprint from ACTIVE even if first badge is DEPRECATED")
        void shouldReturnFingerprintFromActiveEvenIfFirstIsDeprecated() {
            // Given - first badge is DEPRECATED, second is ACTIVE
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenReturn(createMockRegistrationWithFingerprint("DEPRECATED", FINGERPRINT_1));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationWithFingerprint("ACTIVE", FINGERPRINT_2));

            // When
            ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

            // Then - should return VERIFIED (not DEPRECATED_OK) with both fingerprints
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedServerCertFingerprints())
                .containsExactlyInAnyOrder(FINGERPRINT_2, FINGERPRINT_1);
        }

        @Test
        @DisplayName("Should skip REVOKED registration but return ACTIVE one")
        void shouldSkipRevokedButReturnActive() {
            // Given - first badge is REVOKED, second is ACTIVE
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenReturn(createMockRegistrationWithFingerprint("REVOKED", FINGERPRINT_1));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationWithFingerprint("ACTIVE", FINGERPRINT_2));

            // When
            ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

            // Then - should return VERIFIED with only the ACTIVE fingerprint
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedServerCertFingerprints())
                .containsExactly(FINGERPRINT_2);
        }

        @Test
        @DisplayName("Should handle partial fetch failures gracefully")
        void shouldHandlePartialFetchFailures() {
            // Given - first fetch fails, second succeeds
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; version=1.0.1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenThrow(new RuntimeException("Network error"));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationWithFingerprint("ACTIVE", FINGERPRINT_2));

            // When
            ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

            // Then - should still succeed with the working registration
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedServerCertFingerprints())
                .containsExactly(FINGERPRINT_2);
        }

        private TransparencyLog createMockRegistrationWithFingerprint(String status, String fingerprint) {
            CertificateInfo serverCert = new CertificateInfo();
            serverCert.setFingerprint(fingerprint);
            serverCert.setType(CertType.X509_DV_SERVER);

            AttestationsV1 attestations = new AttestationsV1();
            attestations.setServerCert(serverCert);

            AgentV1 agent = new AgentV1();
            agent.setHost(TEST_HOSTNAME);
            agent.setName("Test Agent");
            agent.setVersion("v1.0.0");

            EventV1 event = new EventV1();
            event.setAnsName(TEST_ANS_NAME);
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

    // ==================== Parallel Lookup Tests ====================

    @Nested
    @DisplayName("Parallel Registration Lookup Tests")
    class ParallelLookupTests {

        private static final String AGENT_ID_1 = "aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa";
        private static final String AGENT_ID_2 = "bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb";
        private static final String AGENT_ID_3 = "cccccccc-3333-3333-3333-cccccccccccc";

        @Test
        @DisplayName("Should fetch multiple registrations in parallel")
        void shouldFetchMultipleRegistrationsInParallel() throws Exception {
            // Given - 3 badge records
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_3)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            // Track concurrent calls
            AtomicInteger concurrentCalls = new AtomicInteger(0);
            AtomicInteger maxConcurrent = new AtomicInteger(0);

            // Mock transparency client with concurrent tracking
            when(transparencyClient.getAgentTransparencyLog(anyString())).thenAnswer(invocation -> {
                int current = concurrentCalls.incrementAndGet();
                maxConcurrent.updateAndGet(max -> Math.max(max, current));

                // Wait a bit to ensure overlap
                Thread.sleep(50);

                concurrentCalls.decrementAndGet();
                return createMockRegistrationForHost(TEST_HOSTNAME, "ACTIVE", TEST_FINGERPRINT);
            });

            // Create mock certificate
            X509Certificate cert = mock(X509Certificate.class);

            try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
                certUtils.when(() -> CertificateUtils.extractFqdn(any())).thenReturn(Optional.of(TEST_HOSTNAME));
                certUtils.when(() -> CertificateUtils.getCommonName(any())).thenReturn(TEST_HOSTNAME);
                certUtils.when(() -> CertificateUtils.extractAnsName(any())).thenReturn(Optional.of(TEST_ANS_NAME));
                certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(any())).thenReturn(TEST_FINGERPRINT);
                certUtils.when(() -> CertificateUtils.fingerprintMatches(anyString(), anyString())).thenReturn(true);

                // When
                ClientVerificationResult result = verificationService.verifyClient(cert);

                // Then - verify all 3 registrations were fetched
                verify(transparencyClient, times(3)).getAgentTransparencyLog(anyString());

                // Verify some parallelism occurred (at least 2 concurrent)
                assertThat(maxConcurrent.get()).isGreaterThanOrEqualTo(2);
            }
        }

        @Test
        @DisplayName("Should return ACTIVE match even if it's not the first badge")
        void shouldReturnActiveMatchEvenIfNotFirstBadge() {
            // Given - 3 badges where ACTIVE is the second
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_3)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            // First is DEPRECATED, second is ACTIVE, third is EXPIRED
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "DEPRECATED", TEST_FINGERPRINT));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "ACTIVE", TEST_FINGERPRINT));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_3))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "EXPIRED", TEST_FINGERPRINT));

            X509Certificate cert = mock(X509Certificate.class);

            try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
                setupCertificateUtilsMocks(certUtils);

                // When
                ClientVerificationResult result = verificationService.verifyClient(cert);

                // Then - should return VERIFIED (ACTIVE match)
                assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            }
        }

        @Test
        @DisplayName("Should prefer ACTIVE over DEPRECATED")
        void shouldPreferActiveOverDeprecated() {
            // Given - 2 badges: first DEPRECATED, second ACTIVE
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "DEPRECATED", TEST_FINGERPRINT));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "ACTIVE", TEST_FINGERPRINT));

            X509Certificate cert = mock(X509Certificate.class);

            try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
                setupCertificateUtilsMocks(certUtils);

                // When
                ClientVerificationResult result = verificationService.verifyClient(cert);

                // Then
                assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            }
        }

        @Test
        @DisplayName("Should return DEPRECATED_OK when all matches are deprecated")
        void shouldReturnDeprecatedOkWhenAllDeprecated() {
            // Given
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(anyString()))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "DEPRECATED", TEST_FINGERPRINT));

            X509Certificate cert = mock(X509Certificate.class);

            try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
                setupCertificateUtilsMocks(certUtils);

                // When
                ClientVerificationResult result = verificationService.verifyClient(cert);

                // Then
                assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
            }
        }

        @Test
        @DisplayName("Should handle partial failures gracefully")
        void shouldHandlePartialFailuresGracefully() {
            // Given - 3 badges, one fails
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_3)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_1))
                .thenThrow(new RuntimeException("Network error"));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_2))
                .thenReturn(createMockRegistrationForHost(TEST_HOSTNAME, "ACTIVE", TEST_FINGERPRINT));
            when(transparencyClient.getAgentTransparencyLog(AGENT_ID_3))
                .thenThrow(new RuntimeException("Timeout"));

            X509Certificate cert = mock(X509Certificate.class);

            try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
                setupCertificateUtilsMocks(certUtils);

                // When
                ClientVerificationResult result = verificationService.verifyClient(cert);

                // Then - should still find the working one
                assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            }
        }

        @Test
        @DisplayName("Should return LOOKUP_FAILED when all fetches fail")
        void shouldReturnLookupFailedWhenAllFetchesFail() {
            // Given
            List<RaBadgeRecord> badges = List.of(
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_1),
                RaBadgeRecord.parse("v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/" + AGENT_ID_2)
            );
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(badges);

            when(transparencyClient.getAgentTransparencyLog(anyString()))
                .thenThrow(new RuntimeException("All fail"));

            X509Certificate cert = mock(X509Certificate.class);

            try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
                setupCertificateUtilsMocks(certUtils);

                // When
                ClientVerificationResult result = verificationService.verifyClient(cert);

                // Then
                assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
            }
        }

        private void setupCertificateUtilsMocks(MockedStatic<CertificateUtils> certUtils) {
            certUtils.when(() -> CertificateUtils.extractFqdn(any())).thenReturn(Optional.of(TEST_HOSTNAME));
            certUtils.when(() -> CertificateUtils.getCommonName(any())).thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.extractAnsName(any())).thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(any())).thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(anyString(), anyString())).thenReturn(true);
        }

        private TransparencyLog createMockRegistrationForHost(String host, String status, String fingerprint) {
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
            agent.setHost(host);
            agent.setName("Test Agent");
            agent.setVersion("v1.0.0");

            EventV1 event = new EventV1();
            event.setAnsName("ans://v1.0.0." + host);
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

    // ==================== Helper Methods ====================

    private TransparencyLog createMockRegistration(String status) {
        // Create a properly structured V1 registration
        CertificateInfo serverCert = new CertificateInfo();
        serverCert.setFingerprint(TEST_FINGERPRINT);
        serverCert.setType(CertType.X509_DV_SERVER);

        CertificateInfo identityCert = new CertificateInfo();
        identityCert.setFingerprint(TEST_FINGERPRINT);
        identityCert.setType(CertType.X509_OV_CLIENT);

        AttestationsV1 attestations = new AttestationsV1();
        attestations.setServerCert(serverCert);
        attestations.setIdentityCert(identityCert);

        AgentV1 agent = new AgentV1();
        agent.setHost(TEST_HOSTNAME);
        agent.setName("Test Agent");
        agent.setVersion("v1.0.0");

        EventV1 event = new EventV1();
        event.setAnsName(TEST_ANS_NAME);
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