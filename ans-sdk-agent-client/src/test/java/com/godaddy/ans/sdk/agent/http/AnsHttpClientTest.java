package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.exception.VerificationException;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Tests for AnsHttpClient.
 */
class AnsHttpClientTest {

    private HttpClient mockHttpClient;
    private ConnectionVerifier mockVerifier;
    private MockedStatic<CertificateCapturingTrustManager> mockedStatic;

    @BeforeEach
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
        mockVerifier = mock(ConnectionVerifier.class);
    }

    @AfterEach
    void tearDown() {
        if (mockedStatic != null) {
            mockedStatic.close();
        }
    }

    @Test
    void builderCreatesClient() {
        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        assertNotNull(client);
        assertSame(mockHttpClient, client.getDelegate());
    }

    @Test
    void builderRequiresDelegate() {
        assertThrows(NullPointerException.class, () ->
            AnsHttpClient.builder()
                .connectionVerifier(mockVerifier)
                .verificationPolicy(VerificationPolicy.PKI_ONLY)
                .build());
    }

    @Test
    void builderRequiresVerifier() {
        assertThrows(NullPointerException.class, () ->
            AnsHttpClient.builder()
                .delegate(mockHttpClient)
                .verificationPolicy(VerificationPolicy.PKI_ONLY)
                .build());
    }

    @Test
    void builderRequiresPolicy() {
        assertThrows(NullPointerException.class, () ->
            AnsHttpClient.builder()
                .delegate(mockHttpClient)
                .connectionVerifier(mockVerifier)
                .build());
    }

    @Test
    void builderAcceptsPreVerifyTimeout() {
        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .preVerifyTimeout(Duration.ofSeconds(30))
            .build();

        assertNotNull(client);
    }

    @Test
    void noVerificationCreatesWorkingClient() {
        AnsHttpClient client = AnsHttpClient.noVerification(mockHttpClient);

        assertNotNull(client);
        assertSame(mockHttpClient, client.getDelegate());
    }

    @Test
    void noVerificationRequiresHttpClient() {
        assertThrows(NullPointerException.class, () ->
            AnsHttpClient.noVerification(null));
    }

    @Test
    void clearCacheDoesNotThrow() {
        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        client.clearCache();
        // Should not throw
    }

    @Test
    void invalidateCacheDoesNotThrow() {
        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        client.invalidateCache("example.com", 443);
        // Should not throw
    }

    @Test
    void builderMethodsReturnBuilder() {
        AnsHttpClient.Builder builder = AnsHttpClient.builder();

        assertSame(builder, builder.delegate(mockHttpClient));
        assertSame(builder, builder.connectionVerifier(mockVerifier));
        assertSame(builder, builder.verificationPolicy(VerificationPolicy.PKI_ONLY));
        assertSame(builder, builder.preVerifyTimeout(Duration.ofSeconds(5)));
    }

    @Test
    void noVerificationClientGetDelegate() {
        AnsHttpClient client = AnsHttpClient.noVerification(mockHttpClient);
        assertEquals(mockHttpClient, client.getDelegate());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithVerificationSuccessShouldReturnResponse() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.DANE, "fp123");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify
        assertNotNull(response);
        assertEquals("success", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithVerificationFailureShouldThrowException() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        // Mismatch will trigger retry, so both calls return mismatch
        VerificationResult failResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.DANE, "actual", "expected");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(failResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(failResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify - should throw after retry also fails
        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));

        // preVerify called twice due to retry on mismatch
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithNoCapturedCertificatesShouldThrowWhenVerificationRequired() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify
        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithNoCertificatesAndPkiOnlyShouldSucceed() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify
        assertNotNull(response);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithBadgePreVerificationFailedShouldThrowWhenRequired() throws Exception {
        // Setup mocks
        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgePreVerifyFailed("Certificate revoked")
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify
        VerificationException ex = assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
        assertTrue(ex.getMessage().contains("BADGE"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithVerificationSuccessShouldReturnResponse() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async success");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "fp456");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute
        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        // Verify
        assertNotNull(response);
        assertEquals("async success", response.body());
    }

    @Test
    void sendAsyncWithBadgePreVerificationFailedShouldFail() {
        // Setup mocks
        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgePreVerifyFailed("Expired registration")
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify
        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);
    }

    @Test
    void sendWithCustomPortShouldUseCorrectPort() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 8443).build();
        when(mockVerifier.preVerify(eq("example.com"), eq(8443)))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com:8443/api"))
            .build();

        // Execute
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify
        assertNotNull(response);
    }

    @Test
    void noVerificationClientSendDelegatesToHttpClient() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("direct");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        AnsHttpClient client = AnsHttpClient.noVerification(mockHttpClient);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("direct", response.body());
    }

    @Test
    void noVerificationClientSendAsyncDelegatesToHttpClient() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async direct");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        AnsHttpClient client = AnsHttpClient.noVerification(mockHttpClient);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("async direct", response.body());
    }

    @Test
    void preVerifyCacheIsUsedOnSubsequentCalls() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // First call
        client.send(request, HttpResponse.BodyHandlers.ofString());
        // Second call - should use cache
        client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify preVerify was only called once (cache was used for second call)
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(1))
            .preVerify("example.com", 443);
    }

    @Test
    void clearCacheAllowsNewPreVerification() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // First call
        client.send(request, HttpResponse.BodyHandlers.ofString());

        // Clear cache
        client.clearCache();

        // Second call after cache clear - should call preVerify again
        client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify preVerify was called twice (once before cache clear, once after)
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }

    @Test
    void invalidateCacheForSpecificHostAllowsNewPreVerification() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // First call
        client.send(request, HttpResponse.BodyHandlers.ofString());

        // Invalidate cache for this specific host
        client.invalidateCache("example.com", 443);

        // Second call after invalidation - should call preVerify again
        client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify preVerify was called twice
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithPreVerificationTimeoutFallsBackToEmptyResult() throws Exception {
        // Setup: preVerify returns a future that times out
        CompletableFuture<PreVerificationResult> slowFuture = new CompletableFuture<>();
        // Never complete it - it will timeout

        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(slowFuture);

        // Setup response for after timeout fallback
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .preVerifyTimeout(Duration.ofMillis(100)) // Very short timeout
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute - should complete even though preVerify times out (PKI_ONLY policy)
        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        // Verify - should fall back to empty pre-verification and succeed with PKI_ONLY
        assertNotNull(response);
        assertEquals("success", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithNoCapturedCertificatesShouldFailWhenRequired() {
        // Setup mocks - pre-verification succeeds
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED) // Requires verification
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify
        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);
        assertTrue(ex.getCause().getMessage().contains("No certificates captured"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithVerificationFailureShouldThrowException() {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        // Post-verify returns mismatch - both initial and retry will get same result
        VerificationResult failResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.DANE, "actual", "expected");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(failResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(failResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify - should throw after retry also fails
        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);

        // preVerify called twice due to retry on mismatch
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithPreVerifyExceptionFallsBackToEmptyResult() throws Exception {
        // Setup: preVerify throws exception
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.failedFuture(new RuntimeException("DNS lookup failed")));

        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success after fallback");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute - should succeed despite preVerify failure
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success after fallback", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithNoCapturedCertsAndPkiOnlyShouldSucceed() throws Exception {
        // When PKI_ONLY policy and no certificates captured, should still succeed
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("pki only success");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.PKI_ONLY)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute - PKI_ONLY doesn't require certificate verification
        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("pki only success", response.body());
    }

    // ==================== Retry on Mismatch Tests ====================

    @Test
    @SuppressWarnings("unchecked")
    void sendWithMismatchShouldRetryAndSucceedWithFreshData() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success after retry");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        // First preVerify returns stale data, second returns fresh data
        PreVerificationResult stalePreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("old-fingerprint"))
            .build();
        PreVerificationResult freshPreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("new-fingerprint"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(stalePreResult))
            .thenReturn(CompletableFuture.completedFuture(freshPreResult));

        // First postVerify returns mismatch (stale data), second returns success (fresh data)
        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "old-fingerprint");
        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "actual-fp");

        // Use successive returns for postVerify
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult))
            .thenReturn(List.of(successResult));

        // Use successive returns for combine
        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult)
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute - should succeed after retry with fresh data
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Verify
        assertNotNull(response);
        assertEquals("success after retry", response.body());

        // preVerify should be called twice (once for stale, once for fresh after mismatch)
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithMismatchShouldThrowAfterRetryIfStillMismatch() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("expected-fp"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        // Both attempts return mismatch - actual cert doesn't match expected
        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "expected-fp");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify - should throw after retry also fails
        VerificationException ex = assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
        assertTrue(ex.getMessage().contains("mismatch") || ex.getMessage().contains("MISMATCH"));

        // preVerify should be called twice (initial + retry)
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithErrorShouldNotRetry() throws Exception {
        // ERROR status (not MISMATCH) should not trigger retry
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        // Return ERROR (not MISMATCH) - should not trigger retry
        VerificationResult errorResult = VerificationResult.error(
            VerificationResult.VerificationType.DANE, "DNS resolution failed");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(errorResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(errorResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute and verify - should throw immediately without retry
        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));

        // preVerify should only be called once (no retry for ERROR)
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(1))
            .preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithMismatchShouldRetryAndSucceedWithFreshData() throws Exception {
        // Setup mocks
        mockedStatic = mockStatic(CertificateCapturingTrustManager.class);
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        mockedStatic.when(() -> CertificateCapturingTrustManager.getCapturedCertificates("example.com"))
            .thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async success after retry");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        // First preVerify returns stale data, second returns fresh data
        PreVerificationResult stalePreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("old-fingerprint"))
            .build();
        PreVerificationResult freshPreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("new-fingerprint"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(stalePreResult))
            .thenReturn(CompletableFuture.completedFuture(freshPreResult));

        // First postVerify returns mismatch (stale data), second returns success (fresh data)
        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "old-fingerprint");
        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "actual-fp");

        // Use successive returns for postVerify
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult))
            .thenReturn(List.of(successResult));

        // Use successive returns for combine
        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult)
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        // Execute - should succeed after retry with fresh data
        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        // Verify
        assertNotNull(response);
        assertEquals("async success after retry", response.body());

        // preVerify should be called twice
        org.mockito.Mockito.verify(mockVerifier, org.mockito.Mockito.times(2))
            .preVerify("example.com", 443);
    }
}
