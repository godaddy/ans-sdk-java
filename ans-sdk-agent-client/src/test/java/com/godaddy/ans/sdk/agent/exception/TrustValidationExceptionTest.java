package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.agent.exception.TrustValidationException.ValidationFailureReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Tests for TrustValidationException.
 */
class TrustValidationExceptionTest {

    @Test
    void constructorWithMessageOnly() {
        TrustValidationException ex = new TrustValidationException("Validation failed");

        assertEquals("Validation failed", ex.getMessage());
        assertNull(ex.getCause());
        assertNull(ex.getCertificateSubject());
        assertNull(ex.getReason());
    }

    @Test
    void constructorWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("Certificate error");
        TrustValidationException ex = new TrustValidationException("Validation failed", cause);

        assertEquals("Validation failed", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertNull(ex.getCertificateSubject());
        assertNull(ex.getReason());
    }

    @Test
    void constructorWithMessageAndReason() {
        TrustValidationException ex = new TrustValidationException(
            "Certificate expired", ValidationFailureReason.EXPIRED);

        assertEquals("Certificate expired", ex.getMessage());
        assertEquals(ValidationFailureReason.EXPIRED, ex.getReason());
        assertNull(ex.getCertificateSubject());
        assertNull(ex.getCause());
    }

    @Test
    void constructorWithMessageSubjectAndReason() {
        TrustValidationException ex = new TrustValidationException(
            "Untrusted CA", "CN=agent.example.com", ValidationFailureReason.UNTRUSTED_CA);

        assertEquals("Untrusted CA", ex.getMessage());
        assertEquals("CN=agent.example.com", ex.getCertificateSubject());
        assertEquals(ValidationFailureReason.UNTRUSTED_CA, ex.getReason());
        assertNull(ex.getCause());
    }

    @Test
    void constructorWithAllParameters() {
        RuntimeException cause = new RuntimeException("Chain error");
        TrustValidationException ex = new TrustValidationException(
            "Chain validation failed", cause, "CN=intermediate.ca", ValidationFailureReason.CHAIN_VALIDATION_FAILED);

        assertEquals("Chain validation failed", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals("CN=intermediate.ca", ex.getCertificateSubject());
        assertEquals(ValidationFailureReason.CHAIN_VALIDATION_FAILED, ex.getReason());
    }

    @ParameterizedTest
    @EnumSource(ValidationFailureReason.class)
    void allValidationFailureReasonsCanBeUsed(ValidationFailureReason reason) {
        TrustValidationException ex = new TrustValidationException("Test", reason);

        assertNotNull(ex.getReason());
        assertEquals(reason, ex.getReason());
    }

    @Test
    void validationFailureReasonEnumValues() {
        ValidationFailureReason[] reasons = ValidationFailureReason.values();
        assertEquals(9, reasons.length);

        assertEquals(ValidationFailureReason.UNTRUSTED_CA, ValidationFailureReason.valueOf("UNTRUSTED_CA"));
        assertEquals(ValidationFailureReason.CHAIN_VALIDATION_FAILED,
            ValidationFailureReason.valueOf("CHAIN_VALIDATION_FAILED"));
        assertEquals(ValidationFailureReason.EXPIRED, ValidationFailureReason.valueOf("EXPIRED"));
        assertEquals(ValidationFailureReason.NOT_YET_VALID, ValidationFailureReason.valueOf("NOT_YET_VALID"));
        assertEquals(ValidationFailureReason.REVOKED, ValidationFailureReason.valueOf("REVOKED"));
        assertEquals(ValidationFailureReason.ANS_NAME_MISMATCH, ValidationFailureReason.valueOf("ANS_NAME_MISMATCH"));
        assertEquals(ValidationFailureReason.MISSING_EXTENSIONS,
            ValidationFailureReason.valueOf("MISSING_EXTENSIONS"));
        assertEquals(ValidationFailureReason.TRUST_BUNDLE_LOAD_FAILED,
            ValidationFailureReason.valueOf("TRUST_BUNDLE_LOAD_FAILED"));
        assertEquals(ValidationFailureReason.UNKNOWN, ValidationFailureReason.valueOf("UNKNOWN"));
    }
}
