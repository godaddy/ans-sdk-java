package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult.Status;
import com.godaddy.ans.sdk.agent.verification.VerificationResult.VerificationType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for VerificationException.
 */
class VerificationExceptionTest {

    @Test
    void constructorWithMismatchResult() {
        VerificationResult result = VerificationResult.mismatch(
            VerificationType.DANE, "actualFP", "expectedFP");

        VerificationException ex = new VerificationException(result, "agent.example.com");

        assertSame(result, ex.getResult());
        assertEquals("agent.example.com", ex.getHostname());
        assertEquals(VerificationType.DANE, ex.getVerificationType());
        assertTrue(ex.getMessage().contains("DANE"));
        assertTrue(ex.getMessage().contains("agent.example.com"));
    }

    @Test
    void constructorWithErrorResult() {
        VerificationResult result = VerificationResult.error(
            VerificationType.BADGE, "Transparency log unavailable");

        VerificationException ex = new VerificationException(result, "badge.agent.com");

        assertSame(result, ex.getResult());
        assertEquals("badge.agent.com", ex.getHostname());
        assertEquals(VerificationType.BADGE, ex.getVerificationType());
        assertTrue(ex.getMessage().contains("BADGE"));
        assertTrue(ex.getMessage().contains("badge.agent.com"));
    }

    @Test
    void constructorWithNotFoundResult() {
        VerificationResult result = VerificationResult.notFound(
            VerificationType.DANE, "No TLSA records");

        VerificationException ex = new VerificationException(result, "test.example.com");

        assertEquals(Status.NOT_FOUND, ex.getResult().status());
        assertEquals(VerificationType.DANE, ex.getVerificationType());
    }

    @Test
    void nullResultThrowsException() {
        assertThrows(NullPointerException.class, () ->
            new VerificationException(null, "test.example.com"));
    }

    @Test
    void nullHostnameIsAllowed() {
        VerificationResult result = VerificationResult.error(VerificationType.DANE, "Error");

        VerificationException ex = new VerificationException(result, null);

        assertNotNull(ex.getResult());
        assertEquals(null, ex.getHostname());
    }

    @Test
    void messageFormatContainsTypeHostnameAndReason() {
        VerificationResult result = VerificationResult.mismatch(
            VerificationType.BADGE, "abc123", "def456");

        VerificationException ex = new VerificationException(result, "secure.agent.io");

        String message = ex.getMessage();
        assertTrue(message.contains("BADGE"), "Message should contain verification type");
        assertTrue(message.contains("secure.agent.io"), "Message should contain hostname");
        assertTrue(message.contains("mismatch"), "Message should contain reason");
    }

    @Test
    void allVerificationTypesWork() {
        for (VerificationType type : VerificationType.values()) {
            VerificationResult result = VerificationResult.error(type, "Test error");
            VerificationException ex = new VerificationException(result, "test.com");

            assertEquals(type, ex.getVerificationType());
        }
    }
}
