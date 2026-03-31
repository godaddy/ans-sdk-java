package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.ScittExpectation;
import com.godaddy.ans.sdk.transparency.scitt.ScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.ScittPreVerifyResult;
import com.godaddy.ans.sdk.transparency.scitt.ScittReceipt;
import com.godaddy.ans.sdk.transparency.scitt.ScittVerifier;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScittVerifierAdapterTest {

    private TransparencyClient mockTransparencyClient;
    private ScittVerifier mockScittVerifier;
    private ScittHeaderProvider mockHeaderProvider;
    private Executor directExecutor;
    private ScittVerifierAdapter adapter;
    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        mockTransparencyClient = mock(TransparencyClient.class);
        when(mockTransparencyClient.getBaseUrl()).thenReturn("https://transparency.test.example.com");
        mockScittVerifier = mock(ScittVerifier.class);
        mockHeaderProvider = mock(ScittHeaderProvider.class);
        directExecutor = Runnable::run; // Synchronous executor for testing

        // Generate test key pair
        testKeyPair = VerificationTestHelpers.generateEcKeyPair();
    }

    /**
     * Helper to convert a PublicKey to a Map keyed by hex key ID.
     */
    private Map<String, PublicKey> toRootKeys(PublicKey publicKey) {
        return VerificationTestHelpers.toRootKeys(publicKey);
    }

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create adapter via builder")
        void shouldCreateViaBuilder() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .build();
            assertThat(a).isNotNull();
        }

        @Test
        @DisplayName("Should reject null transparencyClient in builder")
        void shouldRejectNullTransparencyClient() {
            assertThatThrownBy(() -> ScittVerifierAdapter.builder()
                .transparencyClient(null)
                .build())
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should reject null scittVerifier")
        void shouldRejectNullScittVerifier() {
            assertThatThrownBy(() -> new ScittVerifierAdapter(
                mockTransparencyClient, null, mockHeaderProvider, directExecutor))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("scittVerifier cannot be null");
        }

        @Test
        @DisplayName("Should reject null headerProvider")
        void shouldRejectNullHeaderProvider() {
            assertThatThrownBy(() -> new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, null, directExecutor))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("headerProvider cannot be null");
        }

        @Test
        @DisplayName("Should reject null executor")
        void shouldRejectNullExecutor() {
            assertThatThrownBy(() -> new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, mockHeaderProvider, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("executor cannot be null");
        }
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build adapter with TransparencyClient")
        void shouldBuildWithTransparencyClient() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .build();
            assertThat(a).isNotNull();
        }

        @Test
        @DisplayName("Should require TransparencyClient in builder")
        void shouldRequireTransparencyClient() {
            assertThatThrownBy(() -> ScittVerifierAdapter.builder().build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("transparencyClient is required");
        }

        @Test
        @DisplayName("Should build adapter with custom clock skew tolerance")
        void shouldBuildWithCustomClockSkew() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .clockSkewTolerance(Duration.ofMinutes(5))
                .build();
            assertThat(a).isNotNull();
        }

        @Test
        @DisplayName("Should build adapter with custom executor")
        void shouldBuildWithCustomExecutor() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .executor(directExecutor)
                .build();
            assertThat(a).isNotNull();
        }

    }

    @Nested
    @DisplayName("preVerify() tests")
    class PreVerifyTests {

        @BeforeEach
        void setupAdapter() {
            adapter = new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, mockHeaderProvider, directExecutor);
        }

        @Test
        @DisplayName("Should return notPresent when headers are empty")
        void shouldReturnNotPresentWhenHeadersEmpty() throws Exception {
            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.empty());

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.isPresent()).isFalse();
        }

        @Test
        @DisplayName("Should return notPresent when artifacts are incomplete")
        void shouldReturnNotPresentWhenIncomplete() throws Exception {
            ScittHeaderProvider.ScittArtifacts incomplete =
                new ScittHeaderProvider.ScittArtifacts(null, null);
            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(incomplete));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.isPresent()).isFalse();
        }

        @Test
        @DisplayName("Should verify complete artifacts")
        void shouldVerifyCompleteArtifacts() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.isPresent()).isTrue();
            assertThat(result.expectation().isVerified()).isTrue();
        }

        @Test
        @DisplayName("Should return parseError on exception")
        void shouldReturnParseErrorOnException() throws Exception {
            when(mockHeaderProvider.extractArtifacts(any()))
                .thenThrow(new RuntimeException("Parse error"));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should return parseError on verification exception")
        void shouldReturnParseErrorOnVerificationException() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenThrow(new RuntimeException("Verification error"));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should handle async exception via exceptionally")
        void shouldHandleAsyncException() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("Async failure")));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
            assertThat(result.expectation().failureReason()).contains("Async failure");
        }

        @Test
        @DisplayName("Should handle key not found with REJECT decision")
        void shouldHandleKeyNotFoundWithReject() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(java.time.Instant.now().minusSeconds(3600));
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(keyNotFound);

            com.godaddy.ans.sdk.transparency.scitt.RefreshDecision rejectDecision =
                com.godaddy.ans.sdk.transparency.scitt.RefreshDecision.reject("Too old");
            when(mockTransparencyClient.refreshRootKeysIfNeeded(any()))
                .thenReturn(CompletableFuture.completedFuture(rejectDecision));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
        }

        @Test
        @DisplayName("Should handle key not found with DEFER decision")
        void shouldHandleKeyNotFoundWithDefer() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(java.time.Instant.now());
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(keyNotFound);

            com.godaddy.ans.sdk.transparency.scitt.RefreshDecision deferDecision =
                com.godaddy.ans.sdk.transparency.scitt.RefreshDecision.defer("Cooldown active");
            when(mockTransparencyClient.refreshRootKeysIfNeeded(any()))
                .thenReturn(CompletableFuture.completedFuture(deferDecision));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should handle key not found with REFRESHED decision")
        void shouldHandleKeyNotFoundWithRefreshed() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(java.time.Instant.now());
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            ScittExpectation verified = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(keyNotFound)
                .thenReturn(verified);

            Map<String, PublicKey> freshKeys = toRootKeys(testKeyPair.getPublic());
            com.godaddy.ans.sdk.transparency.scitt.RefreshDecision refreshedDecision =
                com.godaddy.ans.sdk.transparency.scitt.RefreshDecision.refreshed(freshKeys);
            when(mockTransparencyClient.refreshRootKeysIfNeeded(any()))
                .thenReturn(CompletableFuture.completedFuture(refreshedDecision));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().isVerified()).isTrue();
        }

        @Test
        @DisplayName("Should handle key not found with null issued-at")
        void shouldHandleKeyNotFoundWithNullIssuedAt() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(null);
            when(receipt.protectedHeader()).thenReturn(null);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(keyNotFound);

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            // Should return original key not found since we can't determine artifact time
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
        }
    }

    @Nested
    @DisplayName("postVerify() tests")
    class PostVerifyTests {

        @BeforeEach
        void setupAdapter() {
            adapter = new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, mockHeaderProvider, directExecutor);
        }

        @Test
        @DisplayName("Should reject null hostname")
        void shouldRejectNullHostname() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.notPresent();

            assertThatThrownBy(() -> adapter.postVerify(null, cert, preResult))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("hostname cannot be null");
        }

        @Test
        @DisplayName("Should reject null server certificate")
        void shouldRejectNullServerCert() {
            ScittPreVerifyResult preResult = ScittPreVerifyResult.notPresent();

            assertThatThrownBy(() -> adapter.postVerify("test.example.com", null, preResult))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("serverCert cannot be null");
        }

        @Test
        @DisplayName("Should reject null preResult")
        void shouldRejectNullPreResult() {
            X509Certificate cert = mock(X509Certificate.class);

            assertThatThrownBy(() -> adapter.postVerify("test.example.com", cert, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("preResult cannot be null");
        }

        @Test
        @DisplayName("Should return NOT_FOUND when SCITT not present")
        void shouldReturnNotFoundWhenNotPresent() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.notPresent();

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return ERROR when pre-verification failed")
        void shouldReturnErrorWhenPreVerificationFailed() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation failedExpectation = ScittExpectation.invalidReceipt("Test failure");
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                failedExpectation, mock(ScittReceipt.class), mock(StatusToken.class));

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.ERROR);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return SUCCESS when post-verification succeeds")
        void shouldReturnSuccessWhenPostVerificationSucceeds() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                expectation, mock(ScittReceipt.class), mock(StatusToken.class));

            ScittVerifier.ScittVerificationResult verifyResult =
                ScittVerifier.ScittVerificationResult.success("abc123");
            when(mockScittVerifier.postVerify(any(), any(), any())).thenReturn(verifyResult);

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return MISMATCH when post-verification fails")
        void shouldReturnMismatchWhenPostVerificationFails() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("expected123"), List.of(), "ans.test", Map.of(), null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                expectation, mock(ScittReceipt.class), mock(StatusToken.class));

            ScittVerifier.ScittVerificationResult verifyResult =
                ScittVerifier.ScittVerificationResult.mismatch("actual456", "Mismatch");
            when(mockScittVerifier.postVerify(any(), any(), any())).thenReturn(verifyResult);

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return MISMATCH with unknown expected when fingerprints empty")
        void shouldReturnMismatchWithUnknownWhenFingerprintsEmpty() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(), List.of(), "ans.test", Map.of(), null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                expectation, mock(ScittReceipt.class), mock(StatusToken.class));

            ScittVerifier.ScittVerificationResult verifyResult =
                ScittVerifier.ScittVerificationResult.mismatch("actual456", "No valid fingerprints");
            when(mockScittVerifier.postVerify(any(), any(), any())).thenReturn(verifyResult);

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
            assertThat(result.expectedFingerprint()).isEqualTo("unknown");
        }

        @Test
        @DisplayName("Should return ERROR with default message when failureReason is null")
        void shouldReturnErrorWithDefaultMessageWhenFailureReasonNull() {
            X509Certificate cert = mock(X509Certificate.class);
            // Create expectation with null failureReason
            ScittExpectation failedExpectation = ScittExpectation.keyNotFound(null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                failedExpectation, mock(ScittReceipt.class), mock(StatusToken.class));

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.ERROR);
            assertThat(result.reason()).contains("SCITT verification failed");
        }
    }

}
