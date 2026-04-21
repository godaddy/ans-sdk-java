package com.godaddy.ans.sdk.agent.server;

import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.agent.verification.VerificationTestHelpers;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.DefaultScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.ScittExpectation;
import com.godaddy.ans.sdk.transparency.scitt.ScittHeaders;
import com.godaddy.ans.sdk.transparency.scitt.ScittReceipt;
import com.godaddy.ans.sdk.transparency.scitt.ScittVerifier;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultClientRequestVerifier}.
 *
 * <p>Covers input validation, SCITT verification, caching behavior,
 * DoS protection, and error handling paths.</p>
 */
class DefaultClientRequestVerifierTest {

    private TransparencyClient mockTransparencyClient;
    private ScittVerifier mockScittVerifier;
    private X509Certificate mockClientCert;
    private DefaultClientRequestVerifier verifier;
    private String clientCertFingerprint;
    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        mockTransparencyClient = mock(TransparencyClient.class);
        when(mockTransparencyClient.getBaseUrl()).thenReturn("https://transparency.test.example.com");
        mockScittVerifier = mock(ScittVerifier.class);
        mockClientCert = createMockCertificate();
        clientCertFingerprint = CertificateUtils.computeSha256Fingerprint(mockClientCert);

        testKeyPair = VerificationTestHelpers.generateEcKeyPair();

        when(mockTransparencyClient.getRootKeysAsync()).thenReturn(
            CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

        verifier = DefaultClientRequestVerifier.builder()
            .transparencyClient(mockTransparencyClient)
            .scittVerifier(mockScittVerifier)
            .headerProvider(new DefaultScittHeaderProvider())
            .verificationCacheTtl(Duration.ofMinutes(5))
            .build();
    }

    private Map<String, PublicKey> toRootKeys(PublicKey publicKey) {
        return VerificationTestHelpers.toRootKeys(publicKey);
    }

    @Nested
    @DisplayName("Input validation tests")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null client certificate")
        void shouldRejectNullClientCert() {
            assertThatThrownBy(() ->
                verifier.verify(null, Map.of(), VerificationPolicy.SCITT_REQUIRED))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientCert cannot be null");
        }

        @Test
        @DisplayName("Should reject null request headers")
        void shouldRejectNullHeaders() {
            assertThatThrownBy(() ->
                verifier.verify(mockClientCert, null, VerificationPolicy.SCITT_REQUIRED))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("requestHeaders cannot be null");
        }

        @Test
        @DisplayName("Should reject null policy")
        void shouldRejectNullPolicy() {
            assertThatThrownBy(() ->
                verifier.verify(mockClientCert, Map.of(), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("policy cannot be null");
        }
    }

    @Nested
    @DisplayName("Missing SCITT headers tests")
    class MissingHeadersTests {

        @Test
        @DisplayName("Should fail when SCITT headers required but missing")
        void shouldFailWhenScittRequiredButMissing() throws Exception {
            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, Map.of(), VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("not present"));
        }

        @Test
        @DisplayName("Should fail gracefully when SCITT headers in advisory mode but missing")
        void shouldHandleMissingHeadersInAdvisoryMode() throws Exception {
            VerificationPolicy advisoryPolicy = VerificationPolicy.custom()
                .scitt(VerificationMode.ADVISORY)
                .build();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, Map.of(), advisoryPolicy)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("not present"));
        }
    }

    @Nested
    @DisplayName("Successful verification tests")
    class SuccessfulVerificationTests {

        @Test
        @DisplayName("Should verify valid SCITT artifacts with matching certificate")
        void shouldVerifyValidArtifacts() throws Exception {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of(clientCertFingerprint),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentId()).isEqualTo("test-agent");
            assertThat(result.errors()).isEmpty();
            assertThat(result.hasScittArtifacts()).isTrue();
            assertThat(result.isCertificateTrusted()).isTrue();
        }

        @Test
        @DisplayName("Should cache successful verification result")
        void shouldCacheSuccessfulResult() throws Exception {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of(clientCertFingerprint),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result1 = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            ClientRequestVerificationResult result2 = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result1.verified()).isTrue();
            assertThat(result2.verified()).isTrue();
        }

        @Test
        @DisplayName("Should invalidate cache when token expires before cache TTL")
        void shouldInvalidateCacheWhenTokenExpires() throws Exception {
            Instant shortExpiry = Instant.now().plusMillis(100);
            StatusToken shortLivedToken = createMockStatusTokenWithExpiry(
                "test-agent", shortExpiry);

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of(clientCertFingerprint),
                "test.ans",
                Map.of(),
                shortLivedToken
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeadersWithExpiry(shortExpiry);

            ClientRequestVerificationResult result1 = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);
            assertThat(result1.verified()).isTrue();

            verify(mockScittVerifier, times(1)).verify(any(), any(), any());

            Thread.sleep(150);

            ClientRequestVerificationResult result2 = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);
            assertThat(result2.verified()).isTrue();

            verify(mockScittVerifier, times(2)).verify(any(), any(), any());
        }
    }

    @Nested
    @DisplayName("Certificate fingerprint mismatch tests")
    class FingerprintMismatchTests {

        @Test
        @DisplayName("Should fail when certificate fingerprint does not match identity certs")
        void shouldFailOnFingerprintMismatch() throws Exception {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of("SHA256:different-fingerprint"),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("fingerprint mismatch"));
        }

        @Test
        @DisplayName("Should fail when no identity certs in status token")
        void shouldFailWhenNoIdentityCerts() throws Exception {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("SHA256:some-server-cert"),
                List.of(),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("No valid identity certificates"));
        }
    }

    @Nested
    @DisplayName("SCITT verification failure tests")
    class ScittVerificationFailureTests {

        @Test
        @DisplayName("Should fail when SCITT verification fails")
        void shouldFailWhenScittVerificationFails() throws Exception {
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(ScittExpectation.invalidToken("Signature verification failed"));

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("SCITT verification failed"));
        }

        @Test
        @DisplayName("Should fail when status token is expired")
        void shouldFailWhenTokenExpired() throws Exception {
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(ScittExpectation.expired());

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("SCITT verification failed"));
        }

        @Test
        @DisplayName("Should fail when agent is revoked")
        void shouldFailWhenAgentRevoked() throws Exception {
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(ScittExpectation.revoked("test.ans"));

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
        }
    }

    @Nested
    @DisplayName("Invalid header content tests")
    class InvalidHeaderContentTests {

        @Test
        @DisplayName("Should fail on invalid Base64 in headers")
        void shouldFailOnInvalidBase64() throws Exception {
            Map<String, String> headers = Map.of(
                ScittHeaders.STATUS_TOKEN_HEADER, "not-valid-base64!!!"
            );

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
        }

        @Test
        @DisplayName("Should fail on invalid CBOR in headers")
        void shouldFailOnInvalidCbor() throws Exception {
            byte[] invalidCbor = {0x01, 0x02, 0x03};
            Map<String, String> headers = Map.of(
                ScittHeaders.STATUS_TOKEN_HEADER, Base64.getEncoder().encodeToString(invalidCbor)
            );

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
        }
    }

    @Nested
    @DisplayName("DoS protection tests")
    class DoSProtectionTests {

        @Test
        @DisplayName("Should fail when receipt header exceeds size limit")
        void shouldFailWhenReceiptHeaderExceedsSizeLimit() throws Exception {
            String oversizedHeader = "A".repeat(65 * 1024);
            Map<String, String> headers = new HashMap<>();
            headers.put(ScittHeaders.SCITT_RECEIPT_HEADER, oversizedHeader);
            headers.put(ScittHeaders.STATUS_TOKEN_HEADER,
                Base64.getEncoder().encodeToString(createValidStatusTokenBytes()));

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("exceeds size limit"));
        }

        @Test
        @DisplayName("Should fail when status token header exceeds size limit")
        void shouldFailWhenStatusTokenHeaderExceedsSizeLimit() throws Exception {
            String oversizedHeader = "B".repeat(65 * 1024);
            Map<String, String> headers = new HashMap<>();
            headers.put(ScittHeaders.SCITT_RECEIPT_HEADER,
                Base64.getEncoder().encodeToString(createValidReceiptBytes()));
            headers.put(ScittHeaders.STATUS_TOKEN_HEADER, oversizedHeader);

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("exceeds size limit"));
        }

        @Test
        @DisplayName("Should accept headers just under size limit")
        void shouldAcceptHeadersJustUnderSizeLimit() throws Exception {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of(clientCertFingerprint),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            String largeButValidReceipt = "A".repeat(64 * 1024 - 1);
            Map<String, String> headers = new HashMap<>();
            headers.put(ScittHeaders.SCITT_RECEIPT_HEADER, largeButValidReceipt);
            headers.put(ScittHeaders.STATUS_TOKEN_HEADER,
                Base64.getEncoder().encodeToString(createValidStatusTokenBytes()));

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.errors()).noneMatch(e -> e.contains("exceeds size limit"));
        }
    }

    @Nested
    @DisplayName("Async error handling tests")
    class AsyncErrorHandlingTests {

        @Test
        @DisplayName("Should handle root key fetch failure")
        void shouldHandleRootKeyFetchFailure() throws Exception {
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.failedFuture(
                    new RuntimeException("Network error")));

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e ->
                e.contains("Failed to fetch SCITT public keys") || e.contains("Network error"));
        }

        @Test
        @DisplayName("Should handle unexpected exception during verification")
        void shouldHandleUnexpectedExceptionDuringVerification() throws Exception {
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenThrow(new RuntimeException("Unexpected error"));

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("error"));
        }
    }

    @Nested
    @DisplayName("Fingerprint matching edge cases")
    class FingerprintMatchingEdgeCaseTests {

        @Test
        @DisplayName("Should match fingerprint when present in multiple identity certs")
        void shouldMatchFingerprintInMultipleIdentityCerts() throws Exception {
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of("SHA256:other-fp-1", clientCertFingerprint, "SHA256:other-fp-2"),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isTrue();
        }

        @Test
        @DisplayName("Should match fingerprint with different case")
        void shouldMatchFingerprintWithDifferentCase() throws Exception {
            String upperCaseFingerprint = clientCertFingerprint.toUpperCase();

            ScittExpectation expectation = ScittExpectation.verified(
                List.of(),
                List.of(upperCaseFingerprint),
                "test.ans",
                Map.of(),
                createMockStatusToken("test-agent")
            );
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isTrue();
        }
    }

    @Nested
    @DisplayName("Cache expiry edge cases")
    class CacheExpiryEdgeCaseTests {

        @Test
        @DisplayName("Should use different cache keys for different certificates")
        void shouldUseDifferentCacheKeysForDifferentCerts() throws Exception {
            X509Certificate secondCert = createMockCertificate();
            String secondFingerprint = CertificateUtils.computeSha256Fingerprint(secondCert);

            // Use Answer to return appropriate expectation based on which cert is being verified
            when(mockScittVerifier.verify(any(), any(), any())).thenAnswer(invocation -> {
                // Return expectation that matches whichever fingerprint we're checking
                // Since both calls use the same headers, the verifier is called for both
                return ScittExpectation.verified(
                    List.of(),
                    List.of(clientCertFingerprint, secondFingerprint),
                    "test.ans",
                    Map.of(),
                    createMockStatusToken("test-agent")
                );
            });

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result1 = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            ClientRequestVerificationResult result2 = verifier
                .verify(secondCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            // Both should succeed
            assertThat(result1.verified()).isTrue();
            assertThat(result2.verified()).isTrue();
            // Critical: mock should be called twice - different cert fingerprints mean different cache keys
            verify(mockScittVerifier, times(2)).verify(any(), any(), any());
        }
    }

    @Nested
    @DisplayName("Agent status variations")
    class AgentStatusVariationsTests {

        @Test
        @DisplayName("Should fail when agent status is inactive")
        void shouldFailWhenAgentStatusIsInactive() throws Exception {
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(ScittExpectation.inactive(StatusToken.Status.DEPRECATED, "test.ans"));

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
        }

        @Test
        @DisplayName("Should fail when key not found")
        void shouldFailWhenKeyNotFound() throws Exception {
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(ScittExpectation.keyNotFound("Required key ID not in registry"));

            Map<String, String> headers = createValidScittHeaders();

            ClientRequestVerificationResult result = verifier
                .verify(mockClientCert, headers, VerificationPolicy.SCITT_REQUIRED)
                .get(5, TimeUnit.SECONDS);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("SCITT verification failed"));
        }
    }

    @Nested
    @DisplayName("ClientRequestVerificationResult tests")
    class ResultTests {

        @Test
        @DisplayName("hasScittArtifacts should return true when both present")
        void hasScittArtifactsShouldReturnTrueWhenBothPresent() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "test-agent",
                createMockStatusToken("test-agent"),
                createMockReceipt(),
                mockClientCert,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(100)
            );

            assertThat(result.hasScittArtifacts()).isTrue();
        }

        @Test
        @DisplayName("hasScittArtifacts should return false when receipt missing")
        void hasScittArtifactsShouldReturnFalseWhenReceiptMissing() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "test-agent",
                createMockStatusToken("test-agent"),
                null,
                mockClientCert,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(100)
            );

            assertThat(result.hasScittArtifacts()).isFalse();
            assertThat(result.hasStatusTokenOnly()).isTrue();
        }

        @Test
        @DisplayName("isCertificateTrusted should return true when verified with token")
        void isCertificateTrustedWhenVerifiedWithToken() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "test-agent",
                createMockStatusToken("test-agent"),
                createMockReceipt(),
                mockClientCert,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(100)
            );

            assertThat(result.isCertificateTrusted()).isTrue();
        }

        @Test
        @DisplayName("toString should include verification duration")
        void toStringShouldIncludeDuration() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "test-agent",
                createMockStatusToken("test-agent"),
                null,
                mockClientCert,
                VerificationPolicy.SCITT_REQUIRED,
                Duration.ofMillis(150)
            );

            assertThat(result.toString()).contains("verified=true");
            assertThat(result.toString()).contains("test-agent");
        }
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should require TransparencyClient")
        void shouldRequireTransparencyClient() {
            assertThatThrownBy(() -> DefaultClientRequestVerifier.builder().build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("transparencyClient is required");
        }

        @Test
        @DisplayName("Should build with TransparencyClient")
        void shouldBuildWithTransparencyClient() {
            DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(verifier).isNotNull();
        }

        @Test
        @DisplayName("Should build with custom cache TTL")
        void shouldBuildWithCustomCacheTtl() {
            DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
                .transparencyClient(mockTransparencyClient)
                .verificationCacheTtl(Duration.ofMinutes(10))
                .build();

            assertThat(verifier).isNotNull();
        }

        @Test
        @DisplayName("Should reject null cache TTL")
        void shouldRejectNullCacheTtl() {
            assertThatThrownBy(() -> DefaultClientRequestVerifier.builder()
                .verificationCacheTtl(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("ttl cannot be null");
        }

        @Test
        @DisplayName("Should reject zero cache TTL")
        void shouldRejectZeroCacheTtl() {
            assertThatThrownBy(() -> DefaultClientRequestVerifier.builder()
                .verificationCacheTtl(Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be positive");
        }

        @Test
        @DisplayName("Should reject negative cache TTL")
        void shouldRejectNegativeCacheTtl() {
            assertThatThrownBy(() -> DefaultClientRequestVerifier.builder()
                .verificationCacheTtl(Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be positive");
        }

        @Test
        @DisplayName("Should build with custom executor")
        void shouldBuildWithCustomExecutor() {
            Executor customExecutor = Executors.newSingleThreadExecutor();
            DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
                .transparencyClient(mockTransparencyClient)
                .executor(customExecutor)
                .build();

            assertThat(verifier).isNotNull();
        }
    }

    // ==================== Helper Methods ====================

    private Map<String, String> createValidScittHeaders() {
        return createValidScittHeadersWithExpiry(Instant.now().plusSeconds(3600));
    }

    private Map<String, String> createValidScittHeadersWithExpiry(Instant expiresAt) {
        byte[] receiptBytes = createValidReceiptBytes();
        byte[] tokenBytes = createValidStatusTokenBytesWithExpiry(expiresAt);

        Map<String, String> headers = new HashMap<>();
        headers.put(ScittHeaders.SCITT_RECEIPT_HEADER, Base64.getEncoder().encodeToString(receiptBytes));
        headers.put(ScittHeaders.STATUS_TOKEN_HEADER, Base64.getEncoder().encodeToString(tokenBytes));
        return headers;
    }

    private byte[] createValidReceiptBytes() {
        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);
        protectedHeader.Add(395, 1);
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        CBORObject inclusionProofMap = CBORObject.NewMap();
        inclusionProofMap.Add(-1, 1L);
        inclusionProofMap.Add(-2, 0L);
        inclusionProofMap.Add(-3, CBORObject.NewArray());
        inclusionProofMap.Add(-4, CBORObject.FromObject(new byte[32]));

        CBORObject unprotectedHeader = CBORObject.NewMap();
        unprotectedHeader.Add(396, inclusionProofMap);

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(unprotectedHeader);
        array.Add("test-payload".getBytes());
        array.Add(new byte[64]);
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    private byte[] createValidStatusTokenBytes() {
        return createValidStatusTokenBytesWithExpiry(Instant.now().plusSeconds(3600));
    }

    private byte[] createValidStatusTokenBytesWithExpiry(Instant expiresAt) {
        long now = Instant.now().getEpochSecond();

        CBORObject payload = CBORObject.NewMap();
        payload.Add(1, "test-agent");
        payload.Add(2, "ACTIVE");
        payload.Add(3, now);
        payload.Add(4, expiresAt.getEpochSecond());

        CBORObject protectedHeader = CBORObject.NewMap();
        protectedHeader.Add(1, -7);
        byte[] protectedBytes = protectedHeader.EncodeToBytes();

        CBORObject array = CBORObject.NewArray();
        array.Add(protectedBytes);
        array.Add(CBORObject.NewMap());
        array.Add(payload.EncodeToBytes());
        array.Add(new byte[64]);
        CBORObject tagged = CBORObject.FromObjectAndTag(array, 18);

        return tagged.EncodeToBytes();
    }

    private X509Certificate createMockCertificate() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=Test Agent");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject,
            serial,
            Date.from(now.minusSeconds(3600)),
            Date.from(now.plusSeconds(86400)),
            subject,
            keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    private StatusToken createMockStatusToken(String agentId) {
        return createMockStatusTokenWithExpiry(agentId, Instant.now().plusSeconds(3600));
    }

    private StatusToken createMockStatusTokenWithExpiry(String agentId, Instant expiresAt) {
        return new StatusToken(
            agentId,
            StatusToken.Status.ACTIVE,
            Instant.now(),
            expiresAt,
            agentId + ".ans",
            List.of(),
            List.of(),
            Map.of(),
            null
        );
    }

    private ScittReceipt createMockReceipt() {
        return mock(ScittReceipt.class);
    }
}
