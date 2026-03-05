package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for DefaultConnectionVerifier.
 */
class DefaultConnectionVerifierTest {

    private DaneVerifier mockDaneVerifier;
    private BadgeVerifier mockBadgeVerifier;
    private X509Certificate mockCert;

    @BeforeEach
    void setUp() {
        mockDaneVerifier = mock(DaneVerifier.class);
        mockBadgeVerifier = mock(BadgeVerifier.class);
        mockCert = mock(X509Certificate.class);
    }

    @Test
    void builderCreatesVerifier() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .build();

        assertNotNull(verifier);
    }

    @Test
    void builderWithoutVerifiers() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();
        assertNotNull(verifier);
    }

    @Test
    void builderMethodsReturnBuilder() {
        DefaultConnectionVerifier.Builder builder = DefaultConnectionVerifier.builder();

        assertSame(builder, builder.daneVerifier(mockDaneVerifier));
        assertSame(builder, builder.badgeVerifier(mockBadgeVerifier));
    }

    @Test
    void preVerifyWithNoVerifiers() throws ExecutionException, InterruptedException {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        PreVerificationResult result = verifier.preVerify("test.com", 443).get();

        assertEquals("test.com", result.hostname());
        assertEquals(443, result.port());
        assertFalse(result.hasDaneExpectation());
        assertFalse(result.hasBadgeExpectation());
    }

    @Test
    void preVerifyWithDaneVerifier() throws ExecutionException, InterruptedException {
        byte[] expectedData = "fingerprint".getBytes();
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(1, 1, expectedData));

        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(expectations)));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("dane.test.com", 443).get();

        assertTrue(result.hasDaneExpectation());
        assertEquals(1, result.daneExpectations().size());
        assertFalse(result.daneDnsError());
        verify(mockDaneVerifier).preVerify("dane.test.com", 443);
    }

    @Test
    void preVerifyWithBadgeVerifier() throws ExecutionException, InterruptedException {
        BadgeVerifier.BadgeExpectation badgeExpectation = BadgeVerifier.BadgeExpectation.registered(
            List.of("fp1", "fp2"), false, null);

        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(badgeExpectation));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .badgeVerifier(mockBadgeVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("badge.test.com", 443).get();

        assertTrue(result.hasBadgeExpectation());
        assertEquals(2, result.badgeFingerprints().size());
        verify(mockBadgeVerifier).preVerify("badge.test.com");
    }

    @Test
    void preVerifyWithBadgePreVerifyFailed() throws ExecutionException, InterruptedException {
        BadgeVerifier.BadgeExpectation badgeExpectation = BadgeVerifier.BadgeExpectation.failed("Certificate revoked");

        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(badgeExpectation));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .badgeVerifier(mockBadgeVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("revoked.test.com", 443).get();

        assertTrue(result.badgePreVerifyFailed());
        assertEquals("Certificate revoked", result.badgeFailureReason());
    }

    @Test
    void postVerifyWithNoVerifiers() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();
        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443).build();

        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertTrue(results.isEmpty());
    }

    @Test
    void postVerifyWithDaneVerifier() {
        VerificationResult daneResult = VerificationResult.success(
            VerificationResult.VerificationType.DANE, "fp123");

        when(mockDaneVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(daneResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443).build();
        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.VerificationType.DANE, results.get(0).type());
    }

    @Test
    void postVerifyWithBadgeVerifier() {
        VerificationResult badgeResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "fp456");

        when(mockBadgeVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(badgeResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .badgeVerifier(mockBadgeVerifier)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443)
            .badgeFingerprints(List.of("fp456"))
            .build();
        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.VerificationType.BADGE, results.get(0).type());
    }

    @Test
    void combineWithSuccessResult() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.success(VerificationResult.VerificationType.DANE, "fp123"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_REQUIRED);

        assertTrue(combined.isSuccess());
    }

    @Test
    void combineWithMismatchAndRequiredMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.mismatch(VerificationResult.VerificationType.DANE, "actual", "expected"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_REQUIRED);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.MISMATCH, combined.status());
    }

    @Test
    void combineWithMismatchAndAdvisoryMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        VerificationPolicy advisoryPolicy = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .build();

        List<VerificationResult> results = List.of(
            VerificationResult.mismatch(VerificationResult.VerificationType.DANE, "actual", "expected"));

        VerificationResult combined = verifier.combine(results, advisoryPolicy);

        // Advisory mode - mismatch is logged but we continue
        assertNotNull(combined);
    }

    @Test
    void combineWithNotFoundAndRequiredMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.notFound(VerificationResult.VerificationType.DANE, "No TLSA records"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_REQUIRED);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.ERROR, combined.status());
    }

    @Test
    void combineWithNotFoundAndAdvisoryMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        VerificationPolicy advisoryPolicy = VerificationPolicy.custom()
            .dane(VerificationMode.ADVISORY)
            .build();

        List<VerificationResult> results = List.of(
            VerificationResult.notFound(VerificationResult.VerificationType.DANE, "No TLSA records"));

        VerificationResult combined = verifier.combine(results, advisoryPolicy);

        // Advisory mode - not found is OK
        assertFalse(combined.shouldFail());
    }

    @Test
    void combineWithEmptyResults() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        VerificationResult combined = verifier.combine(List.of(), VerificationPolicy.PKI_ONLY);

        assertFalse(combined.shouldFail());
        assertTrue(combined.isNotFound());
    }

    @Test
    void combineWithErrorAndRequiredMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.error(VerificationResult.VerificationType.BADGE, "Connection timeout"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.ERROR, combined.status());
    }

    @Test
    void combineWithMultipleResultsPrefersBadgeSuccess() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.notFound(VerificationResult.VerificationType.DANE, "No records"),
            VerificationResult.success(VerificationResult.VerificationType.BADGE, "fp123"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);

        assertTrue(combined.isSuccess());
        assertEquals(VerificationResult.VerificationType.BADGE, combined.type());
    }

    // ==================== DNS Error Handling Tests ====================

    @Test
    void postVerifyReturnsDaneErrorWhenDnsLookupFailed() {
        VerificationResult daneResult = VerificationResult.notFound(
            VerificationResult.VerificationType.DANE, "No TLSA records");

        when(mockDaneVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(daneResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        // Create pre-result with DNS error
        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443)
            .daneDnsError("Connection refused")
            .build();

        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.Status.ERROR, results.get(0).status());
        assertTrue(results.get(0).reason().contains("DNS lookup failed"));
    }

    @Test
    void preVerifyWithDaneVerifierDnsError() throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.dnsError("Network unreachable")));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("dns.error.com", 443).get();

        assertFalse(result.hasDaneExpectation());
        assertTrue(result.daneDnsError());
        assertEquals("Network unreachable", result.daneDnsErrorMessage());
        verify(mockDaneVerifier).preVerify("dns.error.com", 443);
    }

    @Test
    void combineWithDaneErrorAndRequiredModeReturnsError() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.error(VerificationResult.VerificationType.DANE, "DNS lookup failed"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_REQUIRED);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.ERROR, combined.status());
    }
}
