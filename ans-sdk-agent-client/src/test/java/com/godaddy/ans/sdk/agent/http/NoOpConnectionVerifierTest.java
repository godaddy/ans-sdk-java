package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for NoOpConnectionVerifier.
 */
class NoOpConnectionVerifierTest {

    @Test
    void singletonInstanceIsAvailable() {
        assertNotNull(NoOpConnectionVerifier.INSTANCE);
    }

    @Test
    void constructorCreatesNewInstance() {
        NoOpConnectionVerifier verifier = new NoOpConnectionVerifier();
        assertNotNull(verifier);
    }

    @Test
    void preVerifyReturnsCompletedFuture() throws ExecutionException, InterruptedException {
        NoOpConnectionVerifier verifier = new NoOpConnectionVerifier();

        var future = verifier.preVerify("example.com", 443);

        assertTrue(future.isDone());
        PreVerificationResult result = future.get();
        assertNotNull(result);
        assertEquals("example.com", result.hostname());
        assertEquals(443, result.port());
    }

    @Test
    void preVerifyWithDifferentHostAndPort() throws ExecutionException, InterruptedException {
        NoOpConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;

        PreVerificationResult result = verifier.preVerify("agent.test.io", 8443).get();

        assertEquals("agent.test.io", result.hostname());
        assertEquals(8443, result.port());
    }

    @Test
    void postVerifyReturnsEmptyList() {
        NoOpConnectionVerifier verifier = new NoOpConnectionVerifier();
        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443).build();

        List<VerificationResult> results = verifier.postVerify("test.com", null, preResult);

        assertNotNull(results);
        assertTrue(results.isEmpty());
    }

    @Test
    void combineReturnsSkippedResult() {
        NoOpConnectionVerifier verifier = new NoOpConnectionVerifier();

        VerificationResult result = verifier.combine(List.of(), VerificationPolicy.PKI_ONLY);

        assertNotNull(result);
        assertEquals(VerificationResult.Status.NOT_FOUND, result.status());
        assertEquals(VerificationResult.VerificationType.PKI_ONLY, result.type());
        assertTrue(result.reason().contains("PKI only"));
    }

    @Test
    void combineWithDifferentPoliciesReturnsSkipped() {
        NoOpConnectionVerifier verifier = NoOpConnectionVerifier.INSTANCE;

        VerificationResult result1 = verifier.combine(List.of(), VerificationPolicy.DANE_REQUIRED);
        assertFalse(result1.shouldFail());

        VerificationResult result2 = verifier.combine(List.of(), VerificationPolicy.BADGE_REQUIRED);
        assertFalse(result2.shouldFail());

        VerificationResult result3 = verifier.combine(List.of(), VerificationPolicy.FULL);
        assertFalse(result3.shouldFail());
    }

    @Test
    void singletonInstanceReturnsSameReference() {
        assertSame(NoOpConnectionVerifier.INSTANCE, NoOpConnectionVerifier.INSTANCE);
    }
}
