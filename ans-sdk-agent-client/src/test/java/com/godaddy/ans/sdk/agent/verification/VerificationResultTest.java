package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.agent.verification.VerificationResult.Status;
import com.godaddy.ans.sdk.agent.verification.VerificationResult.VerificationType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for VerificationResult.
 */
class VerificationResultTest {

    @Test
    void successCreatesSuccessResult() {
        VerificationResult result = VerificationResult.success(VerificationType.DANE, "abc123");

        assertEquals(Status.SUCCESS, result.status());
        assertEquals(VerificationType.DANE, result.type());
        assertEquals("abc123", result.actualFingerprint());
        assertEquals("abc123", result.expectedFingerprint());
        assertTrue(result.isSuccess());
        assertFalse(result.shouldFail());
        assertFalse(result.isNotFound());
    }

    @Test
    void successWithReasonCreatesSuccessResult() {
        VerificationResult result = VerificationResult.success(
            VerificationType.BADGE, "fp123", "Matched transparency log");

        assertEquals(Status.SUCCESS, result.status());
        assertEquals(VerificationType.BADGE, result.type());
        assertEquals("Matched transparency log", result.reason());
        assertTrue(result.isSuccess());
    }

    @Test
    void mismatchCreatesMismatchResult() {
        VerificationResult result = VerificationResult.mismatch(
            VerificationType.DANE, "actual123", "expected456");

        assertEquals(Status.MISMATCH, result.status());
        assertEquals(VerificationType.DANE, result.type());
        assertEquals("actual123", result.actualFingerprint());
        assertEquals("expected456", result.expectedFingerprint());
        assertTrue(result.reason().contains("mismatch"));
        assertFalse(result.isSuccess());
        assertTrue(result.shouldFail());
    }

    @Test
    void mismatchTruncatesLongFingerprints() {
        String longActual = "0123456789abcdef0123456789abcdef";
        String longExpected = "fedcba9876543210fedcba9876543210";

        VerificationResult result = VerificationResult.mismatch(
            VerificationType.BADGE, longActual, longExpected);

        assertTrue(result.reason().contains("..."));
    }

    @Test
    void notFoundCreatesNotFoundResult() {
        VerificationResult result = VerificationResult.notFound(
            VerificationType.DANE, "No TLSA records found");

        assertEquals(Status.NOT_FOUND, result.status());
        assertEquals(VerificationType.DANE, result.type());
        assertEquals("No TLSA records found", result.reason());
        assertNull(result.actualFingerprint());
        assertNull(result.expectedFingerprint());
        assertTrue(result.isNotFound());
        assertFalse(result.isSuccess());
        assertFalse(result.shouldFail());
    }

    @Test
    void errorCreatesErrorResult() {
        VerificationResult result = VerificationResult.error(
            VerificationType.BADGE, "Connection timeout");

        assertEquals(Status.ERROR, result.status());
        assertEquals(VerificationType.BADGE, result.type());
        assertEquals("Connection timeout", result.reason());
        assertFalse(result.isSuccess());
        assertTrue(result.shouldFail());
    }

    @Test
    void errorFromExceptionCreatesErrorResult() {
        RuntimeException ex = new RuntimeException("DNS lookup failed");

        VerificationResult result = VerificationResult.error(VerificationType.DANE, ex);

        assertEquals(Status.ERROR, result.status());
        assertEquals("DNS lookup failed", result.reason());
    }

    @Test
    void errorFromExceptionWithoutMessageUsesClassName() {
        RuntimeException ex = new RuntimeException();

        VerificationResult result = VerificationResult.error(VerificationType.DANE, ex);

        assertEquals("RuntimeException", result.reason());
    }

    @Test
    void skippedCreatesSkippedResult() {
        VerificationResult result = VerificationResult.skipped("No verification configured");

        assertEquals(Status.NOT_FOUND, result.status());
        assertEquals(VerificationType.PKI_ONLY, result.type());
        assertEquals("No verification configured", result.reason());
        assertTrue(result.isNotFound());
    }

    @ParameterizedTest
    @EnumSource(Status.class)
    void allStatusValuesExist(Status status) {
        assertNotNull(status);
    }

    @ParameterizedTest
    @EnumSource(VerificationType.class)
    void allVerificationTypesExist(VerificationType type) {
        assertNotNull(type);
    }

    @Test
    void statusEnumValues() {
        assertEquals(4, Status.values().length);
        assertEquals(Status.SUCCESS, Status.valueOf("SUCCESS"));
        assertEquals(Status.MISMATCH, Status.valueOf("MISMATCH"));
        assertEquals(Status.NOT_FOUND, Status.valueOf("NOT_FOUND"));
        assertEquals(Status.ERROR, Status.valueOf("ERROR"));
    }

    @Test
    void verificationTypeEnumValues() {
        assertEquals(4, VerificationType.values().length);
        assertEquals(VerificationType.DANE, VerificationType.valueOf("DANE"));
        assertEquals(VerificationType.BADGE, VerificationType.valueOf("BADGE"));
        assertEquals(VerificationType.SCITT, VerificationType.valueOf("SCITT"));
        assertEquals(VerificationType.PKI_ONLY, VerificationType.valueOf("PKI_ONLY"));
    }

    @Test
    void toStringContainsKeyInfo() {
        VerificationResult result = VerificationResult.success(VerificationType.DANE, "fp123");

        String str = result.toString();
        assertTrue(str.contains("DANE"));
        assertTrue(str.contains("SUCCESS"));
    }

    @Test
    void recordAccessors() {
        VerificationResult result = new VerificationResult(
            Status.SUCCESS, VerificationType.BADGE, "reason", "actual", "expected");

        assertEquals(Status.SUCCESS, result.status());
        assertEquals(VerificationType.BADGE, result.type());
        assertEquals("reason", result.reason());
        assertEquals("actual", result.actualFingerprint());
        assertEquals("expected", result.expectedFingerprint());
    }

    @Test
    void mismatchWithShortFingerprints() {
        VerificationResult result = VerificationResult.mismatch(
            VerificationType.DANE, "short", "also");

        // Short fingerprints should not be truncated
        assertFalse(result.reason().contains("..."));
    }

    @Test
    void mismatchWithNullFingerprints() {
        VerificationResult result = VerificationResult.mismatch(
            VerificationType.DANE, null, null);

        assertEquals(Status.MISMATCH, result.status());
    }
}
