package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.transparency.scitt.ScittExpectation;
import com.godaddy.ans.sdk.transparency.scitt.ScittPreVerifyResult;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for PreVerificationResult.
 */
class PreVerificationResultTest {

    @Test
    void builderCreatesBasicResult() {
        PreVerificationResult result = PreVerificationResult.builder("example.com", 443).build();

        assertEquals("example.com", result.hostname());
        assertEquals(443, result.port());
        assertNotNull(result.timestamp());
        assertFalse(result.hasDaneExpectation());
        assertFalse(result.hasBadgeExpectation());
        assertFalse(result.badgePreVerifyFailed());
        assertNull(result.badgeFailureReason());
    }

    @Test
    void builderWithDaneExpectations() {
        byte[] expectedData = "abc123".getBytes();
        DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(
            1, 1, expectedData);

        PreVerificationResult result = PreVerificationResult.builder("dane.test.com", 443)
            .daneExpectations(List.of(expectation))
            .build();

        assertTrue(result.hasDaneExpectation());
        assertEquals(1, result.daneExpectations().size());
        assertEquals(1, result.daneExpectations().get(0).selector());
    }

    @Test
    void builderWithBadgeFingerprints() {
        PreVerificationResult result = PreVerificationResult.builder("badge.test.com", 443)
            .badgeFingerprints(List.of("fp1", "fp2", "fp3"))
            .build();

        assertTrue(result.hasBadgeExpectation());
        assertEquals(3, result.badgeFingerprints().size());
        assertTrue(result.badgeFingerprints().contains("fp1"));
    }

    @Test
    void builderWithBadgePreVerifyFailed() {
        PreVerificationResult result = PreVerificationResult.builder("revoked.test.com", 443)
            .badgePreVerifyFailed("Certificate has been revoked")
            .build();

        assertTrue(result.badgePreVerifyFailed());
        assertEquals("Certificate has been revoked", result.badgeFailureReason());
    }

    @Test
    void builderWithNullLists() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .daneExpectations(null)
            .badgeFingerprints(null)
            .build();

        assertFalse(result.hasDaneExpectation());
        assertFalse(result.hasBadgeExpectation());
        assertTrue(result.daneExpectations().isEmpty());
        assertTrue(result.badgeFingerprints().isEmpty());
    }

    @Test
    void recordConstructorDefensiveCopiesLists() {
        List<String> fingerprints = new java.util.ArrayList<>();
        fingerprints.add("fp1");

        PreVerificationResult result = new PreVerificationResult(
            "test.com", 443, List.of(), false, null, fingerprints, false, null, null, Instant.now());

        assertEquals(1, result.badgeFingerprints().size());
        // The list should be immutable
    }

    @Test
    void toStringContainsKeyInfo() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .badgeFingerprints(List.of("fp1"))
            .build();

        String str = result.toString();
        assertTrue(str.contains("test.com"));
        assertTrue(str.contains("443"));
        assertTrue(str.contains("hasBadge=true"));
        assertTrue(str.contains("hasScitt="));
    }

    @Test
    void hasDaneExpectationWithEmptyList() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .daneExpectations(List.of())
            .build();

        assertFalse(result.hasDaneExpectation());
    }

    @Test
    void hasBadgeExpectationWithEmptyList() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .badgeFingerprints(List.of())
            .build();

        assertFalse(result.hasBadgeExpectation());
    }

    @Test
    void differentPorts() {
        PreVerificationResult result1 = PreVerificationResult.builder("test.com", 443).build();
        PreVerificationResult result2 = PreVerificationResult.builder("test.com", 8443).build();

        assertEquals(443, result1.port());
        assertEquals(8443, result2.port());
    }

    // ==================== DNS Error Tests ====================

    @Test
    void daneDnsErrorSetsErrorFields() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .daneDnsError("Connection refused")
            .build();

        assertTrue(result.daneDnsError());
        assertEquals("Connection refused", result.daneDnsErrorMessage());
        assertFalse(result.hasDaneExpectation());
    }

    @Test
    void danePreVerifyResultSetsAllFields() {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));

        DaneVerifier.PreVerifyResult daneResult = DaneVerifier.PreVerifyResult.success(expectations);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .danePreVerifyResult(daneResult)
            .build();

        assertTrue(result.hasDaneExpectation());
        assertEquals(1, result.daneExpectations().size());
        assertFalse(result.daneDnsError());
        assertNull(result.daneDnsErrorMessage());
    }

    @Test
    void danePreVerifyResultWithDnsErrorSetsErrorFields() {
        DaneVerifier.PreVerifyResult daneResult = DaneVerifier.PreVerifyResult.dnsError("Timeout");

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .danePreVerifyResult(daneResult)
            .build();

        assertFalse(result.hasDaneExpectation());
        assertTrue(result.daneDnsError());
        assertEquals("Timeout", result.daneDnsErrorMessage());
    }

    @Test
    void danePreVerifyResultWithNullHandledGracefully() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .danePreVerifyResult(null)
            .build();

        assertFalse(result.hasDaneExpectation());
        assertFalse(result.daneDnsError());
    }

    @Test
    void defaultDnsErrorFieldsAreFalse() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443).build();

        assertFalse(result.daneDnsError());
        assertNull(result.daneDnsErrorMessage());
    }

    // ==================== SCITT Tests ====================

    @Test
    void hasScittExpectationReturnsFalseWhenNull() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443).build();

        assertFalse(result.hasScittExpectation());
    }

    @Test
    void hasScittExpectationReturnsFalseWhenNotPresent() {
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.notPresent();

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertFalse(result.hasScittExpectation());
    }

    @Test
    void hasScittExpectationReturnsTrueWhenPresent() {
        ScittExpectation expectation = ScittExpectation.verified(
            List.of("fp1"), List.of(), "test.ans", Map.of(), null);
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertTrue(result.hasScittExpectation());
    }

    @Test
    void hasScittExpectationReturnsTrueForParseError() {
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.parseError("Failed to parse receipt");

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        // Parse error means headers were present, just couldn't parse them
        assertTrue(result.hasScittExpectation());
    }

    @Test
    void scittPreVerifySucceededReturnsFalseWhenNull() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443).build();

        assertFalse(result.scittPreVerifySucceeded());
    }

    @Test
    void scittPreVerifySucceededReturnsFalseWhenNotPresent() {
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.notPresent();

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertFalse(result.scittPreVerifySucceeded());
    }

    @Test
    void scittPreVerifySucceededReturnsFalseWhenParseError() {
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.parseError("Invalid CBOR");

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertFalse(result.scittPreVerifySucceeded());
    }

    @Test
    void scittPreVerifySucceededReturnsFalseForInvalidReceipt() {
        ScittExpectation expectation = ScittExpectation.invalidReceipt("Signature verification failed");
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertFalse(result.scittPreVerifySucceeded());
    }

    @Test
    void scittPreVerifySucceededReturnsFalseForExpired() {
        ScittExpectation expectation = ScittExpectation.expired();
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertFalse(result.scittPreVerifySucceeded());
    }

    @Test
    void scittPreVerifySucceededReturnsFalseForRevoked() {
        ScittExpectation expectation = ScittExpectation.revoked("test.ans");
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertFalse(result.scittPreVerifySucceeded());
    }

    @Test
    void scittPreVerifySucceededReturnsTrueWhenVerified() {
        ScittExpectation expectation = ScittExpectation.verified(
            List.of("server-fp"), List.of("identity-fp"), "test.ans", Map.of(), null);
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertTrue(result.scittPreVerifySucceeded());
    }

    @Test
    void builderWithScittPreVerifyResult() {
        ScittExpectation expectation = ScittExpectation.verified(
            List.of("fp1", "fp2"), List.of(), "test.ans", Map.of("https", "SHA256:abc"), null);
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        assertNotNull(result.scittPreVerifyResult());
        assertEquals(scittResult, result.scittPreVerifyResult());
        assertTrue(result.hasScittExpectation());
        assertTrue(result.scittPreVerifySucceeded());
    }

    @Test
    void toStringIncludesScittInfo() {
        ScittExpectation expectation = ScittExpectation.verified(
            List.of("fp1"), List.of(), "test.ans", Map.of(), null);
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittResult)
            .build();

        String str = result.toString();
        assertTrue(str.contains("hasScitt=true"));
    }

    @Test
    void toStringShowsScittFalseWhenNotPresent() {
        PreVerificationResult result = PreVerificationResult.builder("test.com", 443).build();

        String str = result.toString();
        assertTrue(str.contains("hasScitt=false"));
    }

    @Test
    void recordConstructorWithScittPreVerifyResult() {
        ScittExpectation expectation = ScittExpectation.verified(
            List.of("fp1"), List.of(), "test.ans", Map.of(), null);
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(expectation, null, null);

        PreVerificationResult result = new PreVerificationResult(
            "test.com", 443, List.of(), false, null, List.of(), false, null, scittResult, Instant.now());

        assertTrue(result.hasScittExpectation());
        assertTrue(result.scittPreVerifySucceeded());
        assertEquals(scittResult, result.scittPreVerifyResult());
    }
}
