package com.godaddy.ans.sdk.agent.protocol;

import com.godaddy.ans.sdk.agent.exception.ProtocolException;
import com.godaddy.ans.sdk.agent.http.AnsHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HttpApiClientTest {

    @Mock
    private AnsHttpClient ansHttpClient;

    @Mock
    private HttpResponse<String> httpResponse;

    private HttpApiClient client;

    @BeforeEach
    void setUp() {
        client = new HttpApiClient(ansHttpClient, "https://example.com");
    }

    @Test
    void constructorWithValidParametersShouldSucceed() {
        // Given/When
        HttpApiClient client = new HttpApiClient(ansHttpClient, "https://example.com");

        // Then
        assertThat(client.getBaseUrl()).isEqualTo("https://example.com");
        assertThat(client.getTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void constructorWithTrailingSlashShouldNormalize() {
        // Given/When
        HttpApiClient client = new HttpApiClient(ansHttpClient, "https://example.com/");

        // Then
        assertThat(client.getBaseUrl()).isEqualTo("https://example.com");
    }

    @Test
    void constructorWithCustomTimeoutShouldSetTimeout() {
        // Given/When
        HttpApiClient client = new HttpApiClient(ansHttpClient, "https://example.com",
            Duration.ofMinutes(5));

        // Then
        assertThat(client.getTimeout()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void constructorWithNullHttpClientShouldThrowException() {
        assertThatThrownBy(() -> new HttpApiClient(null, "https://example.com"))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("HTTP client");
    }

    @Test
    void constructorWithNullBaseUrlShouldThrowException() {
        assertThatThrownBy(() -> new HttpApiClient(ansHttpClient, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Base URL");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"data\":\"test\"}");

        // When
        String result = client.get("/api/v1/data");

        // Then
        assertThat(result).isEqualTo("{\"data\":\"test\"}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"hello\"}");

        // When
        TestResponse result = client.get("/api/v1/data", TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("hello");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith404ResponseShouldThrowProtocolException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.of("req-123"));

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(404);
        when(httpResponse.body()).thenReturn("Not Found");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("not found")
            .extracting("statusCode")
            .isEqualTo(404);
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith401ResponseShouldThrowAuthException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(401);
        when(httpResponse.body()).thenReturn("Unauthorized");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("Authentication");
    }

    @Test
    @SuppressWarnings("unchecked")
    void postWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(201);
        when(httpResponse.body()).thenReturn("{\"id\":\"123\"}");

        // When
        String result = client.post("/api/v1/data", new TestRequest("hello"));

        // Then
        assertThat(result).contains("123");
    }

    @Test
    @SuppressWarnings("unchecked")
    void putWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"updated\":true}");

        // When
        String result = client.put("/api/v1/data/123", new TestRequest("updated"));

        // Then
        assertThat(result).contains("true");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(204);
        when(httpResponse.body()).thenReturn("");

        // When
        String result = client.delete("/api/v1/data/123");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestWithNetworkErrorShouldThrowAgentConnectionException() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenThrow(new IOException("Connection refused"));

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(com.godaddy.ans.sdk.agent.exception.AgentConnectionException.class)
            .hasMessageContaining("Network error");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith403ResponseShouldThrowAuthException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(403);
        when(httpResponse.body()).thenReturn("Forbidden");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("authorization");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith500ResponseShouldThrowProtocolException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(500);
        when(httpResponse.body()).thenReturn("Internal Server Error");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("500");
    }

    @Test
    @SuppressWarnings("unchecked")
    void customRequestMethodShouldWork() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"result\":\"ok\"}");

        // When
        String result = client.request("PATCH", "/api/v1/data", "{\"field\":\"value\"}", null);

        // Then
        assertThat(result).contains("ok");
    }

    @Test
    @SuppressWarnings("unchecked")
    void customRequestWithHeadersShouldWork() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");

        java.util.Map<String, String> headers = java.util.Map.of("X-Custom", "value");

        // When
        String result = client.request("GET", "/api/v1/data", null, headers);

        // Then
        assertThat(result).isEqualTo("{}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void postWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(201);
        when(httpResponse.body()).thenReturn("{\"value\":\"created\"}");

        // When
        TestResponse result = client.post("/api/v1/data", new TestRequest("test"), TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("created");
    }

    @Test
    @SuppressWarnings("unchecked")
    void putWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"updated\"}");

        // When
        TestResponse result = client.put("/api/v1/data/123", new TestRequest("update"), TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("updated");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"deleted\"}");

        // When
        TestResponse result = client.delete("/api/v1/data/123", TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("deleted");
    }

    @Test
    void pathWithoutLeadingSlashShouldBeNormalized() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");

        // When - path without leading slash
        String result = client.get("api/v1/data");

        // Then - should succeed without error
        assertThat(result).isEqualTo("{}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestWithInterruptionShouldThrowAgentConnectionException() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenThrow(new InterruptedException("Thread interrupted"));

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(com.godaddy.ans.sdk.agent.exception.AgentConnectionException.class)
            .hasMessageContaining("interrupted");
    }

    // ==================== Async Method Tests ====================

    @Test
    @SuppressWarnings("unchecked")
    void getAsyncWithTypedResponseShouldDeserialize() throws Exception {
        // Given - async methods use CompletableFuture.supplyAsync which calls sync methods internally
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"async-typed\"}");

        // When
        java.util.concurrent.CompletableFuture<TestResponse> future =
            client.getAsync("/api/v1/data", TestResponse.class);
        TestResponse result = future.get();

        // Then
        assertThat(result.value).isEqualTo("async-typed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void postAsyncWithTypedResponseShouldDeserialize() throws Exception {
        // Given - async methods use CompletableFuture.supplyAsync which calls sync methods internally
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(201);
        when(httpResponse.body()).thenReturn("{\"value\":\"async-created\"}");

        // When
        java.util.concurrent.CompletableFuture<TestResponse> future =
            client.postAsync("/api/v1/data", new TestRequest("test"), TestResponse.class);
        TestResponse result = future.get();

        // Then
        assertThat(result.value).isEqualTo("async-created");
    }

    @Test
    @SuppressWarnings("unchecked")
    void asyncRequestWithErrorStatusShouldFailFuture() throws Exception {
        // Given - async methods use CompletableFuture.supplyAsync which calls sync methods internally
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(500);
        when(httpResponse.body()).thenReturn("Internal Server Error");
        when(httpResponse.headers()).thenReturn(headers);

        // When
        java.util.concurrent.CompletableFuture<TestResponse> future =
            client.getAsync("/api/v1/data", TestResponse.class);

        // Then
        assertThatThrownBy(future::get)
            .isInstanceOf(java.util.concurrent.ExecutionException.class)
            .hasCauseInstanceOf(ProtocolException.class);
    }

    @Test
    void constructorWithAuthProviderShouldSetProvider() {
        // Given
        com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider authProvider =
            com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider.bearer("test-token");

        // When
        HttpApiClient clientWithAuth = new HttpApiClient(
            ansHttpClient, "https://example.com", Duration.ofSeconds(30), authProvider);

        // Then
        assertThat(clientWithAuth.getTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void constructorWithAllParametersShouldWork() {
        // Given
        com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider authProvider =
            com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider.bearer("test-token");
        java.util.concurrent.Executor executor = java.util.concurrent.Executors.newSingleThreadExecutor();

        // When
        HttpApiClient clientWithAll = new HttpApiClient(
            ansHttpClient, "https://example.com", Duration.ofSeconds(45), authProvider, executor);

        // Then
        assertThat(clientWithAll.getTimeout()).isEqualTo(Duration.ofSeconds(45));
    }

    @Test
    void constructorWithNullTimeoutShouldThrow() {
        assertThatThrownBy(() -> new HttpApiClient(ansHttpClient, "https://example.com", null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Timeout");
    }

    @Test
    void constructorWithNullExecutorShouldThrow() {
        assertThatThrownBy(() -> new HttpApiClient(ansHttpClient, "https://example.com",
            Duration.ofSeconds(30), null, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Executor");
    }

    @Test
    void postWithUnserializableObjectShouldThrowProtocolException() {
        // Given - an object that Jackson cannot serialize
        Object unserializable = new Object() {
            // Jackson cannot serialize objects without getters or @JsonProperty
            public Object getSelfReference() {
                return this;
            } // Creates circular reference
        };

        // When/Then - serialization should fail
        assertThatThrownBy(() -> client.post("/api/v1/data", unserializable))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("serialize");
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestWithAuthHeadersShouldIncludeAuth() throws Exception {
        // Given
        com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider authProvider =
            com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider.bearer("test-token");

        HttpApiClient clientWithAuth = new HttpApiClient(
            ansHttpClient, "https://example.com", Duration.ofSeconds(30), authProvider);

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");

        // When
        String result = clientWithAuth.get("/api/v1/data");

        // Then
        assertThat(result).isEqualTo("{}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void authProviderShouldReceiveMethodAndUri() throws Exception {
        // Given - a custom auth provider that requires method and URI for signing
        java.util.concurrent.atomic.AtomicReference<String> capturedMethod =
                new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<java.net.URI> capturedUri =
                new java.util.concurrent.atomic.AtomicReference<>();

        com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider signingProvider =
            new com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider() {
                @Override
                public java.util.Map<String, String> getHeaders() {
                    return java.util.Map.of();
                }

                @Override
                public java.util.Map<String, String> getHeaders(String method, java.net.URI uri) {
                    capturedMethod.set(method);
                    capturedUri.set(uri);
                    return java.util.Map.of("X-Signature", "sig-for-" + method + "-" + uri.getPath());
                }
            };

        HttpApiClient clientWithSigning = new HttpApiClient(
            ansHttpClient, "https://example.com", Duration.ofSeconds(30), signingProvider);

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");

        // When
        clientWithSigning.post("/api/v1/agents", new TestRequest("data"));

        // Then - the auth provider should have been called with method and URI
        assertThat(capturedMethod.get()).isEqualTo("POST");
        assertThat(capturedUri.get().getPath()).isEqualTo("/api/v1/agents");
    }

    // ==================== Error Response Handling Tests ====================

    @Test
    @SuppressWarnings("unchecked")
    void getTypedWith404ShouldReturnApiErrorNotDeserializationError() throws Exception {
        // Given - Server returns 404 with error JSON that doesn't match expected type
        // The error message from the API should be preserved, not masked by deserialization failure
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.of("req-456"));

        // Mock the typed response - when body handler processes error response
        HttpResponse<TestResponse> typedResponse = mock(HttpResponse.class);
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn((HttpResponse) typedResponse);
        when(typedResponse.statusCode()).thenReturn(404);
        when(typedResponse.body()).thenReturn(null); // Error response couldn't be deserialized as TestResponse
        when(typedResponse.headers()).thenReturn(headers);

        // When/Then - Should throw ProtocolException with 404 info, not deserialization error
        assertThatThrownBy(() -> client.get("/api/v1/agents/unknown", TestResponse.class))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("not found")
            .extracting("statusCode")
            .isEqualTo(404);
    }

    @Test
    @SuppressWarnings("unchecked")
    void postTypedWith500ShouldReturnApiErrorNotDeserializationError() throws Exception {
        // Given - Server returns 500 with error JSON
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.of("req-789"));

        HttpResponse<TestResponse> typedResponse = mock(HttpResponse.class);
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn((HttpResponse) typedResponse);
        when(typedResponse.statusCode()).thenReturn(500);
        when(typedResponse.body()).thenReturn(null); // Error response couldn't be deserialized
        when(typedResponse.headers()).thenReturn(headers);

        // When/Then - Should throw ProtocolException with 500 info
        assertThatThrownBy(() -> client.post("/api/v1/agents", new TestRequest("data"), TestResponse.class))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("500");
    }

    // Test helper classes
    private static class TestRequest {
        public String value;

        TestRequest(String value) {
            this.value = value;
        }
    }

    private static final class TestResponse {
        public String value;
    }
}
