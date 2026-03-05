package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DaneVerifier}.
 * Covers test scenarios 7.1-7.5 from test-cases.md (DANE/TLSA Verification).
 */
class DaneVerifierTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    @Mock
    private DaneTlsaVerifier tlsaVerifier;

    private DaneVerifier daneVerifier;

    // Use synchronous executor for testing
    private final Executor syncExecutor = Runnable::run;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        daneVerifier = new DaneVerifier(tlsaVerifier, syncExecutor);
    }

    // ==================== 7.1 DNSSEC Validated, TLSA Matches ====================

    @Test
    @DisplayName("7.1 Should pass when DNSSEC validated and TLSA matches")
    void shouldPassWhenDnssecValidatedAndTlsaMatches() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String actualFingerprint = CertificateUtils.computeSha256Fingerprint(cert);
        byte[] fingerprintBytes = hexToBytes(actualFingerprint.replace("SHA256:", ""));

        // Mock getTlsaExpectations to return expectation with matching fingerprint
        // selector=0 (full cert), matchingType=1 (SHA256)
        DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, fingerprintBytes);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(expectation));

        // When - pre-verify (single DNS call, no TLS connection)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have expectations
        assertThat(preResult.expectations()).hasSize(1);
        assertThat(preResult.isDnsError()).isFalse();

        // Verify only getTlsaExpectations was called (not hasTlsaRecord or verifyTlsa)
        verify(tlsaVerifier).getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);
        verify(tlsaVerifier, never()).hasTlsaRecord(anyString(), anyInt());
        verify(tlsaVerifier, never()).verifyTlsa(anyString(), anyInt());

        // When - post-verify with matching cert
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should succeed
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    // ==================== 7.2 DNSSEC Validated, TLSA Mismatch ====================

    @Test
    @DisplayName("7.2 Should reject when DNSSEC validated but TLSA mismatches")
    void shouldRejectWhenDnssecValidatedButTlsaMismatches() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);
        byte[] differentFingerprint = new byte[32]; // Random - won't match
        new SecureRandom().nextBytes(differentFingerprint);

        // Mock getTlsaExpectations to return expectation with DIFFERENT fingerprint
        DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, differentFingerprint);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(expectation));

        // When - pre-verify (single DNS call, no TLS connection)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have expectations
        assertThat(preResult.expectations()).hasSize(1);

        // When - post-verify with mismatched cert
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should fail with mismatch
        assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    // ==================== 7.3 No DNSSEC Present ====================

    @Test
    @DisplayName("7.3 Should skip DANE when no DNSSEC present")
    void shouldSkipDaneWhenNoDnssecPresent() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock getTlsaExpectations to return empty list (no TLSA record)
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of());

        // When - pre-verify (single DNS call, no TLS connection)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have no expectations
        assertThat(preResult.expectations()).isEmpty();
        assertThat(preResult.isDnsError()).isFalse();

        // When - post-verify with empty expectations
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should return NOT_FOUND (DANE skipped, not an error)
        assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
        assertThat(result.reason()).contains("No TLSA record");
    }

    // ==================== 7.4 DNSSEC Validation Failure ====================

    @Test
    @DisplayName("7.4 Should return DNS error when DNSSEC validation fails")
    void shouldRejectWhenDnssecValidationFails() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock getTlsaExpectations to throw exception (DNSSEC validation failed)
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenThrow(new RuntimeException("DNSSEC validation failed"));

        // When - pre-verify (single DNS call that fails)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should indicate DNS error
        assertThat(preResult.expectations()).isEmpty();
        assertThat(preResult.isDnsError()).isTrue();
        assertThat(preResult.errorMessage()).contains("DNSSEC validation failed");

        // When - post-verify with empty expectations
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should return NOT_FOUND (treat as no valid DANE for postVerify)
        // Note: The caller (DefaultConnectionVerifier) should check isDnsError() first
        assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
    }

    // ==================== 7.5 Multiple TLSA Records (Renewal) ====================

    @Test
    @DisplayName("7.5 Should pass when first TLSA record matches during renewal")
    void shouldPassWhenFirstTlsaRecordMatchesDuringRenewal() throws Exception {
        // Given - create a test certificate (the currently active cert)
        X509Certificate activeCert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String activeFingerprint = CertificateUtils.computeSha256Fingerprint(activeCert);
        byte[] activeFingerprintBytes = hexToBytes(activeFingerprint.replace("SHA256:", ""));

        // Also create a "next" fingerprint for upcoming rotation
        byte[] nextFingerprintBytes = new byte[32];
        new SecureRandom().nextBytes(nextFingerprintBytes);

        // Mock getTlsaExpectations to return multiple expectations
        // Active cert's record is first (current), next cert's record is second (pre-published for rotation)
        DaneTlsaVerifier.TlsaExpectation activeExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, activeFingerprintBytes);
        DaneTlsaVerifier.TlsaExpectation nextExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, nextFingerprintBytes);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(activeExpectation, nextExpectation));

        // When - pre-verify (single DNS call, returns ALL expectations)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have both expectations
        assertThat(preResult.expectations()).hasSize(2);

        // When - post-verify with active cert (matches first expectation)
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, activeCert, preResult.expectations());

        // Then - should succeed since active cert matches first TLSA record
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    @Test
    @DisplayName("7.5b Should pass when ANY TLSA record matches (certificate rotation)")
    void shouldPassWhenAnyTlsaRecordMatchesDuringRotation() throws Exception {
        // This test verifies that during certificate rotation, the server can use
        // the NEW certificate even if the old cert's TLSA record is listed first.
        // postVerify tries ALL expectations and succeeds if ANY matches.

        // Given - certificate that matches second record (not first)
        X509Certificate rotatedCert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String rotatedFingerprint = CertificateUtils.computeSha256Fingerprint(rotatedCert);
        byte[] rotatedFingerprintBytes = hexToBytes(rotatedFingerprint.replace("SHA256:", ""));

        byte[] oldFingerprintBytes = new byte[32];
        new SecureRandom().nextBytes(oldFingerprintBytes);

        // Old record first, rotated cert's record second
        DaneTlsaVerifier.TlsaExpectation oldExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, oldFingerprintBytes);
        DaneTlsaVerifier.TlsaExpectation rotatedExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, rotatedFingerprintBytes);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(oldExpectation, rotatedExpectation));

        // When - pre-verify returns ALL expectations
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have both expectations
        assertThat(preResult.expectations()).hasSize(2);

        // When - post-verify with rotated cert (matches SECOND expectation)
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, rotatedCert, preResult.expectations());

        // Then - should SUCCEED because postVerify tries ALL expectations
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    @Test
    @DisplayName("7.5c Should handle pre-verify exception gracefully")
    void shouldHandlePreVerifyExceptionGracefully() throws Exception {
        // Given - TLSA lookup throws exception
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenThrow(new RuntimeException("DNS query timeout"));

        // When - pre-verify
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should return DNS error with empty expectations
        assertThat(preResult.expectations()).isEmpty();
        assertThat(preResult.isDnsError()).isTrue();
        assertThat(preResult.errorMessage()).contains("DNS query timeout");
    }

    // ==================== PreVerifyResult Tests ====================

    @Test
    @DisplayName("PreVerifyResult.success creates successful result")
    void preVerifyResultSuccessCreatesSuccessfulResult() {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));

        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.success(expectations);

        assertThat(result.expectations()).hasSize(1);
        assertThat(result.isDnsError()).isFalse();
        assertThat(result.errorMessage()).isNull();
        assertThat(result.hasExpectations()).isTrue();
    }

    @Test
    @DisplayName("PreVerifyResult.success with null creates empty expectations")
    void preVerifyResultSuccessWithNullCreatesEmptyExpectations() {
        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.success(null);

        assertThat(result.expectations()).isEmpty();
        assertThat(result.isDnsError()).isFalse();
        assertThat(result.hasExpectations()).isFalse();
    }

    @Test
    @DisplayName("PreVerifyResult.dnsError creates error result")
    void preVerifyResultDnsErrorCreatesErrorResult() {
        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.dnsError("Connection refused");

        assertThat(result.expectations()).isEmpty();
        assertThat(result.isDnsError()).isTrue();
        assertThat(result.errorMessage()).isEqualTo("Connection refused");
        assertThat(result.hasExpectations()).isFalse();
    }

    @Test
    @DisplayName("PreVerifyResult.toString for success")
    void preVerifyResultToStringForSuccess() {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));

        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.success(expectations);

        assertThat(result.toString()).contains("expectations=1");
    }

    @Test
    @DisplayName("PreVerifyResult.toString for DNS error")
    void preVerifyResultToStringForDnsError() {
        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.dnsError("Timeout");

        assertThat(result.toString()).contains("dnsError=Timeout");
    }

    @Test
    @DisplayName("preVerifyExpectations returns expectations list")
    void preVerifyExpectationsReturnsExpectationsList() throws Exception {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(expectations);

        List<DaneTlsaVerifier.TlsaExpectation> result =
            daneVerifier.preVerifyExpectations(TEST_HOSTNAME, TEST_PORT).join();

        assertThat(result).hasSize(1);
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

    /**
     * Converts hex string to byte array.
     */
    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        // Remove colons if present
        hex = hex.replace(":", "").replace(" ", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ==================== DanePolicy Tests ====================

    @Test
    @DisplayName("DanePolicy.DISABLED should not verify")
    void danePolicyDisabledShouldNotVerify() {
        assertThat(DanePolicy.DISABLED.shouldVerify()).isFalse();
        assertThat(DanePolicy.DISABLED.isRequired()).isFalse();
    }

    @Test
    @DisplayName("DanePolicy.VALIDATE_IF_PRESENT should verify but not require")
    void danePolicyValidateIfPresentShouldVerifyButNotRequire() {
        assertThat(DanePolicy.VALIDATE_IF_PRESENT.shouldVerify()).isTrue();
        assertThat(DanePolicy.VALIDATE_IF_PRESENT.isRequired()).isFalse();
    }

    @Test
    @DisplayName("DanePolicy.REQUIRED should verify and require")
    void danePolicyRequiredShouldVerifyAndRequire() {
        assertThat(DanePolicy.REQUIRED.shouldVerify()).isTrue();
        assertThat(DanePolicy.REQUIRED.isRequired()).isTrue();
    }

    // ==================== DnsResolverConfig Tests ====================

    @Test
    @DisplayName("DnsResolverConfig.CLOUDFLARE should have 1.1.1.1")
    void dnsResolverConfigCloudflareShouldHaveCorrectAddress() {
        assertThat(DnsResolverConfig.CLOUDFLARE.getPrimaryAddress()).isEqualTo("1.1.1.1");
        assertThat(DnsResolverConfig.CLOUDFLARE.getSecondaryAddress()).isEqualTo("1.0.0.1");
        assertThat(DnsResolverConfig.CLOUDFLARE.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("DnsResolverConfig.GOOGLE should have 8.8.8.8")
    void dnsResolverConfigGoogleShouldHaveCorrectAddress() {
        assertThat(DnsResolverConfig.GOOGLE.getPrimaryAddress()).isEqualTo("8.8.8.8");
        assertThat(DnsResolverConfig.GOOGLE.getSecondaryAddress()).isEqualTo("8.8.4.4");
        assertThat(DnsResolverConfig.GOOGLE.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("DnsResolverConfig.QUAD9 should have 9.9.9.9")
    void dnsResolverConfigQuad9ShouldHaveCorrectAddress() {
        assertThat(DnsResolverConfig.QUAD9.getPrimaryAddress()).isEqualTo("9.9.9.9");
        assertThat(DnsResolverConfig.QUAD9.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("DnsResolverConfig.SYSTEM should have null addresses")
    void dnsResolverConfigSystemShouldHaveNullAddresses() {
        assertThat(DnsResolverConfig.SYSTEM.getPrimaryAddress()).isNull();
        assertThat(DnsResolverConfig.SYSTEM.getSecondaryAddress()).isNull();
        assertThat(DnsResolverConfig.SYSTEM.isSystemResolver()).isTrue();
    }

    // ==================== DaneConfig Tests ====================

    @Test
    @DisplayName("DaneConfig.defaults() should have expected values")
    void daneConfigDefaultsShouldHaveExpectedValues() {
        DaneConfig config = DaneConfig.defaults();

        assertThat(config.policy()).isEqualTo(DanePolicy.VALIDATE_IF_PRESENT);
        assertThat(config.resolver()).isEqualTo(DnsResolverConfig.CLOUDFLARE);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
        assertThat(config.cacheTtl()).isEqualTo(DaneConfig.DEFAULT_CACHE_TTL);
    }

    @Test
    @DisplayName("DaneConfig.disabled() should have disabled policy")
    void daneConfigDisabledShouldHaveDisabledPolicy() {
        DaneConfig config = DaneConfig.disabled();

        assertThat(config.policy()).isEqualTo(DanePolicy.DISABLED);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
    }

    @Test
    @DisplayName("DaneConfig builder should work correctly")
    void daneConfigBuilderShouldWorkCorrectly() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.REQUIRED)
            .resolver(DnsResolverConfig.GOOGLE)
            .cacheTtl(java.time.Duration.ofMinutes(30))
            .build();

        assertThat(config.policy()).isEqualTo(DanePolicy.REQUIRED);
        assertThat(config.resolver()).isEqualTo(DnsResolverConfig.GOOGLE);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
        assertThat(config.cacheTtl()).isEqualTo(java.time.Duration.ofMinutes(30));
    }

    @Test
    @DisplayName("DaneConfig builder with VALIDATE_IN_CODE mode")
    void daneConfigBuilderWithValidateInCodeMode() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.REQUIRED)
            .resolver(DnsResolverConfig.SYSTEM)
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .cacheTtl(java.time.Duration.ofMinutes(15))
            .build();

        assertThat(config.policy()).isEqualTo(DanePolicy.REQUIRED);
        assertThat(config.resolver()).isEqualTo(DnsResolverConfig.SYSTEM);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
        assertThat(config.cacheTtl()).isEqualTo(java.time.Duration.ofMinutes(15));
    }

    // ==================== DnssecValidationMode Tests ====================

    @Test
    @DisplayName("DnssecValidationMode.TRUST_RESOLVER should require DNSSEC resolver")
    void dnssecValidationModeTrustResolverShouldRequireDnssecResolver() {
        assertThat(DnssecValidationMode.TRUST_RESOLVER.isInCodeValidation()).isFalse();
        assertThat(DnssecValidationMode.TRUST_RESOLVER.requiresDnssecResolver()).isTrue();
    }

    @Test
    @DisplayName("DnssecValidationMode.VALIDATE_IN_CODE should not require DNSSEC resolver")
    void dnssecValidationModeValidateInCodeShouldNotRequireDnssecResolver() {
        assertThat(DnssecValidationMode.VALIDATE_IN_CODE.isInCodeValidation()).isTrue();
        assertThat(DnssecValidationMode.VALIDATE_IN_CODE.requiresDnssecResolver()).isFalse();
    }

    // ==================== DefaultDaneTlsaVerifier Config Tests ====================

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with DISABLED policy should skip verification")
    void defaultDaneTlsaVerifierWithDisabledPolicyShouldSkipVerification() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getPolicy()).isEqualTo(DanePolicy.DISABLED);

        // Verify that verifyTlsa returns skipped result
        DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);
        assertThat(result.isSkipped()).isTrue();
        assertThat(result.reason()).contains("disabled");
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with DISABLED policy should return false for hasTlsaRecord")
    void defaultDaneTlsaVerifierWithDisabledPolicyShouldReturnFalseForHasTlsaRecord() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Should return false without making DNS query
        assertThat(verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT)).isFalse();
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with DISABLED policy should return empty expectations")
    void defaultDaneTlsaVerifierWithDisabledPolicyShouldReturnEmptyExpectations() throws Exception {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Should return empty list without making DNS query
        java.util.List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);
        assertThat(expectations).isEmpty();
    }

    @Test
    @DisplayName("TlsaResult.skipped should work correctly")
    void tlsaResultSkippedShouldWorkCorrectly() {
        DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.skipped("Test reason");

        assertThat(result.verified()).isFalse();
        assertThat(result.isSkipped()).isTrue();
        assertThat(result.reason()).isEqualTo("Test reason");
        assertThat(result.matchType()).isEqualTo("SKIPPED");
    }

    // ==================== DefaultDaneTlsaVerifier ValidationMode Tests ====================

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with TRUST_RESOLVER mode")
    void defaultDaneTlsaVerifierWithTrustResolverMode() {
        DaneConfig config = DaneConfig.builder()
            .validationMode(DnssecValidationMode.TRUST_RESOLVER)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with VALIDATE_IN_CODE mode")
    void defaultDaneTlsaVerifierWithValidateInCodeMode() {
        DaneConfig config = DaneConfig.builder()
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .resolver(DnsResolverConfig.SYSTEM)  // Can use system resolver with in-code validation
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with VALIDATE_IN_CODE and DISABLED policy should skip")
    void defaultDaneTlsaVerifierWithValidateInCodeAndDisabledPolicyShouldSkip() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Verify that policy takes precedence - still skips even with VALIDATE_IN_CODE
        DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);
        assertThat(result.isSkipped()).isTrue();
        assertThat(result.reason()).contains("disabled");
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier defaults to TRUST_RESOLVER mode")
    void defaultDaneTlsaVerifierDefaultsToTrustResolverMode() {
        DaneConfig config = DaneConfig.defaults();
        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
    }

    // ==================== TLSA Lookup Caching Tests ====================

    @Test
    @DisplayName("Cache should start empty")
    void cacheShouldStartEmpty() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED) // Disabled to avoid DNS
            .cacheTtl(java.time.Duration.ofMinutes(5))
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("clearCache should remove all entries")
    void clearCacheShouldRemoveAllEntries() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .cacheTtl(java.time.Duration.ofMinutes(5))
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Cache starts empty
        assertThat(verifier.cacheSize()).isZero();

        // Clear should work even when empty
        verifier.clearCache();
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("invalidate should work without error on non-existent entry")
    void invalidateShouldWorkOnNonExistentEntry() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .cacheTtl(java.time.Duration.ofMinutes(5))
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Should not throw even if entry doesn't exist
        verifier.invalidate("nonexistent.example.com", 443);
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("Cache should be disabled when cacheTtl is zero")
    void cacheShouldBeDisabledWhenTtlIsZero() throws Exception {
        // Use a testable verifier that tracks DNS calls
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ZERO) // Caching disabled
                .build()
        );

        // First call
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);

        // Second call - should still do DNS lookup since caching is disabled
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(2);

        // Cache should remain empty
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("Cache should store results when cacheTtl is positive")
    void cacheShouldStoreResultsWhenTtlIsPositive() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // First call - should do DNS lookup
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Second call - should use cache, not DNS
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1); // Still 1, used cache
        assertThat(verifier.cacheSize()).isEqualTo(1);
    }

    @Test
    @DisplayName("Cache should store different entries for different hosts")
    void cacheShouldStoreDifferentEntriesForDifferentHosts() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Look up first host
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Look up second host
        verifier.getTlsaExpectations("host2.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(2);

        // Look up first host again - should use cache
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(2); // Only 2 DNS lookups total
    }

    @Test
    @DisplayName("Cache should store different entries for different ports")
    void cacheShouldStoreDifferentEntriesForDifferentPorts() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Look up port 443
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Look up port 8443 - different cache entry
        verifier.getTlsaExpectations("test.example.com", 8443);
        assertThat(verifier.cacheSize()).isEqualTo(2);
    }

    @Test
    @DisplayName("invalidate should remove specific cache entry")
    void invalidateShouldRemoveSpecificCacheEntry() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Populate cache with two entries
        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(2);

        // Invalidate one entry
        verifier.invalidate("host1.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Next lookup for host1 should do DNS again
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(3); // 2 initial + 1 after invalidate
    }

    @Test
    @DisplayName("clearCache should remove all cache entries")
    void clearCacheShouldRemoveAllCacheEntries() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Populate cache
        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        verifier.getTlsaExpectations("host3.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(3);

        // Clear all
        verifier.clearCache();
        assertThat(verifier.cacheSize()).isZero();

        // Next lookups should all do DNS
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(4); // 3 initial + 1 after clear
    }

    @Test
    @DisplayName("Empty TLSA results should also be cached")
    void emptyTlsaResultsShouldAlsoBeCached() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Look up host with no TLSA records
        List<DaneTlsaVerifier.TlsaExpectation> result1 = verifier.getTlsaExpectations("no-tlsa.example.com", 443);
        assertThat(result1).isEmpty();
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);
        assertThat(verifier.cacheSize()).isEqualTo(1); // Empty result is cached

        // Second lookup should use cache
        List<DaneTlsaVerifier.TlsaExpectation> result2 = verifier.getTlsaExpectations("no-tlsa.example.com", 443);
        assertThat(result2).isEmpty();
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1); // No additional DNS lookup
    }

    // ==================== Testable Subclass for Caching Tests ====================

    /**
     * Testable subclass that overrides DNS lookup to avoid real network calls.
     * Tracks the number of DNS lookups to verify caching behavior.
     */
    private static class TestableDefaultDaneTlsaVerifier extends DefaultDaneTlsaVerifier {
        private int dnsLookupCount = 0;

        TestableDefaultDaneTlsaVerifier(DaneConfig config) {
            super(config);
        }

        int getDnsLookupCount() {
            return dnsLookupCount;
        }

        @Override
        protected List<TlsaRecordData> performDnsLookup(String hostname, int port) {
            dnsLookupCount++;
            // Return empty list to simulate no TLSA records found
            // This avoids real DNS lookups while still exercising the caching logic
            return List.of();
        }
    }
}
