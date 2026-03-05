package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.transparency.verification.ServerVerificationResult;
import com.godaddy.ans.sdk.transparency.verification.ServerVerifier;
import com.godaddy.ans.sdk.transparency.verification.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.concurrent.Executor;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BadgeVerifier}.
 */
class BadgeVerifierTest {

    private static final String TEST_HOSTNAME = "agent.example.com";

    @Mock
    private ServerVerifier serverVerifier;

    private BadgeVerifier badgeVerifier;

    // Use synchronous executor for testing
    private final Executor syncExecutor = Runnable::run;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        badgeVerifier = new BadgeVerifier(serverVerifier, syncExecutor);
    }

    // ==================== Fingerprint Match ====================

    @Test
    @DisplayName("Should pass when fingerprint matches transparency log registration")
    void shouldPassWhenFingerprintMatches() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String actualFingerprint = CertificateUtils.computeSha256Fingerprint(cert);

        // Mock the verification service to return the same fingerprint
        ServerVerificationResult serverResult = ServerVerificationResult.builder()
            .status(VerificationStatus.VERIFIED)
            .expectedServerCertFingerprint(actualFingerprint)
            .expectedAgentHost(TEST_HOSTNAME)
            .build();
        when(serverVerifier.verifyServer(TEST_HOSTNAME)).thenReturn(serverResult);

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // Then - expectation should have the fingerprint
        assertThat(expectation.isRegisteredAgent()).isTrue();
        assertThat(expectation.expectedFingerprints()).containsExactly(actualFingerprint);

        // When - post-verify with matching cert
        VerificationResult result = badgeVerifier.postVerify(TEST_HOSTNAME, cert, expectation);

        // Then - should succeed
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.BADGE);
    }

    // ==================== Fingerprint Mismatch ====================

    @Test
    @DisplayName("Should reject when fingerprint mismatches")
    void shouldRejectWhenFingerprintMismatches() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock the verification service to return a DIFFERENT fingerprint
        ServerVerificationResult serverResult = ServerVerificationResult.builder()
            .status(VerificationStatus.VERIFIED)
            .expectedServerCertFingerprint("SHA256:different1234567890abcdef1234567890abcdef1234567890abcdef12345678")
            .expectedAgentHost(TEST_HOSTNAME)
            .build();
        when(serverVerifier.verifyServer(TEST_HOSTNAME)).thenReturn(serverResult);

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // Then - expectation should have the expected fingerprint
        assertThat(expectation.isRegisteredAgent()).isTrue();

        // When - post-verify with mismatched cert
        VerificationResult result = badgeVerifier.postVerify(TEST_HOSTNAME, cert, expectation);

        // Then - should fail with mismatch
        assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.BADGE);
        assertThat(result.reason()).contains("mismatch");
    }

    // ==================== Not an ANS Agent ====================

    @Test
    @DisplayName("Should return NOT_FOUND when host is not an ANS agent")
    void shouldReturnNotFoundWhenNotAnsAgent() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock the verification service to return NOT_ANS_AGENT
        ServerVerificationResult serverResult = ServerVerificationResult.builder()
            .status(VerificationStatus.NOT_ANS_AGENT)
            .build();
        when(serverVerifier.verifyServer(TEST_HOSTNAME)).thenReturn(serverResult);

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // Then - expectation should indicate not registered
        assertThat(expectation.isRegisteredAgent()).isFalse();

        // When - post-verify
        VerificationResult result = badgeVerifier.postVerify(TEST_HOSTNAME, cert, expectation);

        // Then - should return NOT_FOUND
        assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
        assertThat(result.reason()).contains("not a registered ANS agent");
    }

    // ==================== Deprecated Registration ====================

    @Test
    @DisplayName("Should pass with warning when registration is DEPRECATED")
    void shouldPassWithWarningWhenDeprecated() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String actualFingerprint = CertificateUtils.computeSha256Fingerprint(cert);

        // Mock the verification service to return DEPRECATED_OK
        ServerVerificationResult serverResult = ServerVerificationResult.builder()
            .status(VerificationStatus.DEPRECATED_OK)
            .expectedServerCertFingerprint(actualFingerprint)
            .expectedAgentHost(TEST_HOSTNAME)
            .warningMessage("Registration is deprecated")
            .build();
        when(serverVerifier.verifyServer(TEST_HOSTNAME)).thenReturn(serverResult);

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // Then - expectation should indicate deprecated
        assertThat(expectation.isRegisteredAgent()).isTrue();
        assertThat(expectation.isDeprecated()).isTrue();

        // When - post-verify
        VerificationResult result = badgeVerifier.postVerify(TEST_HOSTNAME, cert, expectation);

        // Then - should succeed with deprecation note
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.reason()).contains("DEPRECATED");
    }

    // ==================== Pre-verification Failure ====================

    @Test
    @DisplayName("Should return ERROR when pre-verification failed (revoked/expired)")
    void shouldReturnErrorWhenPreVerificationFailed() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock the verification service to return REGISTRATION_INVALID (revoked)
        ServerVerificationResult serverResult = ServerVerificationResult.builder()
            .status(VerificationStatus.REGISTRATION_INVALID)
            .warningMessage("Registration status: REVOKED")
            .build();
        when(serverVerifier.verifyServer(TEST_HOSTNAME)).thenReturn(serverResult);

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // Then - expectation should indicate failure
        assertThat(expectation.preVerificationFailed()).isTrue();

        // When - post-verify
        VerificationResult result = badgeVerifier.postVerify(TEST_HOSTNAME, cert, expectation);

        // Then - should return ERROR
        assertThat(result.status()).isEqualTo(VerificationResult.Status.ERROR);
        assertThat(result.reason()).contains("REVOKED");
    }

    // ==================== Edge Cases ====================

    @Test
    @DisplayName("Should handle pre-verification exception gracefully")
    void shouldHandlePreVerificationException() {
        // Given - mock throws exception
        when(serverVerifier.verifyServer(TEST_HOSTNAME))
            .thenThrow(new RuntimeException("Network error"));

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // Then - should return failed expectation
        assertThat(expectation.preVerificationFailed()).isTrue();
        assertThat(expectation.warningMessage()).contains("Network error");
    }

    @Test
    @DisplayName("Should handle missing fingerprint in registration")
    void shouldHandleMissingFingerprintInRegistration() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock the verification service to return success but NO fingerprint
        ServerVerificationResult serverResult = ServerVerificationResult.builder()
            .status(VerificationStatus.VERIFIED)
            .expectedServerCertFingerprint(null) // Missing fingerprint
            .expectedAgentHost(TEST_HOSTNAME)
            .build();
        when(serverVerifier.verifyServer(TEST_HOSTNAME)).thenReturn(serverResult);

        // When - pre-verify
        BadgeVerifier.BadgeExpectation expectation = badgeVerifier.preVerify(TEST_HOSTNAME).join();

        // When - post-verify
        VerificationResult result = badgeVerifier.postVerify(TEST_HOSTNAME, cert, expectation);

        // Then - should return ERROR (no fingerprint to compare)
        assertThat(result.status()).isEqualTo(VerificationResult.Status.ERROR);
        assertThat(result.reason()).contains("fingerprint");
    }

    // ==================== Helper Methods ====================

    /**
     * Creates a self-signed test certificate with the given subject DN.
     */
    private X509Certificate createTestCertificate(String subjectDn) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name issuer = new X500Name(subjectDn);
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
            .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));
    }
}
