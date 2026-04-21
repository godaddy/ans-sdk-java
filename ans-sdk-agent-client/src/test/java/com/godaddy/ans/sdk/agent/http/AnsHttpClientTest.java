package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.exception.VerificationException;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for AnsHttpClient.
 */
class AnsHttpClientTest {

    private HttpClient mockHttpClient;
    private ConnectionVerifier mockVerifier;
    private CapturedCertificateProvider mockCertProvider;

    @BeforeEach
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
        mockVerifier = mock(ConnectionVerifier.class);
        mockCertProvider = mock(CapturedCertificateProvider.class);
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
        assertSame(builder, builder.certProvider(mockCertProvider));
    }

    @Test
    void noVerificationClientGetDelegate() {
        AnsHttpClient client = AnsHttpClient.noVerification(mockHttpClient);
        assertEquals(mockHttpClient, client.getDelegate());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithVerificationSuccessShouldReturnResponse() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success", response.body());
        verify(mockCertProvider).clearCapturedCertificates("example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithVerificationFailureShouldThrowException() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithNoCapturedCertificatesShouldThrowWhenVerificationRequired() throws Exception {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithNoCertificatesAndPkiOnlyShouldSucceed() throws Exception {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithBadgePreVerificationFailedShouldThrowWhenRequired() throws Exception {
        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgePreVerifyFailed("Certificate revoked")
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        VerificationException ex = assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
        assertTrue(ex.getMessage().contains("BADGE"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithVerificationSuccessShouldReturnResponse() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("async success", response.body());
    }

    @Test
    void sendAsyncWithBadgePreVerificationFailedShouldFail() {
        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgePreVerifyFailed("Expired registration")
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);
    }

    @Test
    void sendWithCustomPortShouldUseCorrectPort() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com:8443/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

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
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
        client.send(request, HttpResponse.BodyHandlers.ofString());

        verify(mockVerifier, times(1)).preVerify("example.com", 443);
    }

    @Test
    void clearCacheAllowsNewPreVerification() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
        client.clearCache();
        client.send(request, HttpResponse.BodyHandlers.ofString());

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    void invalidateCacheForSpecificHostAllowsNewPreVerification() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
        client.invalidateCache("example.com", 443);
        client.send(request, HttpResponse.BodyHandlers.ofString());

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithPreVerificationTimeoutFallsBackToEmptyResult() throws Exception {
        CompletableFuture<PreVerificationResult> slowFuture = new CompletableFuture<>();

        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(slowFuture);

        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .preVerifyTimeout(Duration.ofMillis(100))
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("success", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithNoCapturedCertificatesShouldFailWhenRequired() {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);
        assertTrue(ex.getCause().getMessage().contains("No certificates captured"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithVerificationFailureShouldThrowException() {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithPreVerifyExceptionFallsBackToEmptyResult() throws Exception {
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.failedFuture(new RuntimeException("DNS lookup failed")));

        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success after fallback", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithNoCapturedCertsAndPkiOnlyShouldSucceed() throws Exception {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("pki only success", response.body());
    }

    // ==================== Retry on Mismatch Tests ====================

    @Test
    @SuppressWarnings("unchecked")
    void sendWithMismatchShouldRetryAndSucceedWithFreshData() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success after retry");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult stalePreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("old-fingerprint"))
            .build();
        PreVerificationResult freshPreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("new-fingerprint"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(stalePreResult))
            .thenReturn(CompletableFuture.completedFuture(freshPreResult));

        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "old-fingerprint");
        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "actual-fp");

        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult))
            .thenReturn(List.of(successResult));

        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult)
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success after retry", response.body());
        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithMismatchShouldThrowAfterRetryIfStillMismatch() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("expected-fp"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        VerificationException ex = assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
        assertTrue(ex.getMessage().contains("mismatch") || ex.getMessage().contains("MISMATCH"));
        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithErrorShouldNotRetry() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

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
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));

        verify(mockVerifier, times(1)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithMismatchShouldRetryAndSucceedWithFreshData() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async success after retry");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult stalePreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("old-fingerprint"))
            .build();
        PreVerificationResult freshPreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("new-fingerprint"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(stalePreResult))
            .thenReturn(CompletableFuture.completedFuture(freshPreResult));

        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "old-fingerprint");
        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "actual-fp");

        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult))
            .thenReturn(List.of(successResult));

        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult)
            .thenReturn(successResult);

        AnsHttpClient client = AnsHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("async success after retry", response.body());
        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }
}
