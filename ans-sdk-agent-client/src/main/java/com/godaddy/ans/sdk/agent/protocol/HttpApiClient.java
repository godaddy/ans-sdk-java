package com.godaddy.ans.sdk.agent.protocol;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.agent.exception.AgentConnectionException;
import com.godaddy.ans.sdk.agent.exception.ProtocolException;
import com.godaddy.ans.sdk.agent.http.AnsHttpClient;
import com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * HTTP-API client for communicating with remote ANS agents over mTLS.
 *
 * <p>This client provides methods for making REST API calls to remote agents.
 * All requests are made over mTLS, presenting the calling agent's identity
 * certificate to the remote agent.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * HttpApiClient client = new HttpApiClient(httpClient, "https://remote-agent.example.com");
 *
 * // GET request
 * MyResponse response = client.get("/api/v1/resource", MyResponse.class);
 *
 * // POST request
 * MyResponse response = client.post("/api/v1/resource", requestBody, MyResponse.class);
 * }</pre>
 */
public final class HttpApiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpApiClient.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    private static final String PROTOCOL_NAME = "HTTP-API";

    private final AnsHttpClient httpClient;
    private final String baseUrl;
    private final ObjectMapper objectMapper;
    private final Duration timeout;
    private final HttpAuthHeadersProvider httpAuthHeadersProvider;
    private final Executor executor;

    /**
     * Creates a new HTTP-API client using the shared ANS I/O executor.
     *
     * @param httpClient the verifying HTTP client (performs verification outside TLS handshake)
     * @param baseUrl the base URL of the remote agent
     * @see AnsExecutors#sharedIoExecutor()
     */
    public HttpApiClient(AnsHttpClient httpClient, String baseUrl) {
        this(httpClient, baseUrl, DEFAULT_TIMEOUT, null, AnsExecutors.sharedIoExecutor());
    }

    /**
     * Creates a new HTTP-API client with custom timeout.
     *
     * @param httpClient the verifying HTTP client
     * @param baseUrl the base URL of the remote agent
     * @param timeout the request timeout
     */
    public HttpApiClient(AnsHttpClient httpClient, String baseUrl, Duration timeout) {
        this(httpClient, baseUrl, timeout, null, AnsExecutors.sharedIoExecutor());
    }

    /**
     * Creates a new HTTP-API client with custom timeout and authentication.
     *
     * @param httpClient the verifying HTTP client (performs verification outside TLS handshake)
     * @param baseUrl the base URL of the remote agent
     * @param timeout the request timeout
     * @param httpAuthHeadersProvider the authentication provider (may be null)
     */
    public HttpApiClient(AnsHttpClient httpClient, String baseUrl, Duration timeout,
                         HttpAuthHeadersProvider httpAuthHeadersProvider) {
        this(httpClient, baseUrl, timeout, httpAuthHeadersProvider, AnsExecutors.sharedIoExecutor());
    }

    /**
     * Creates a new HTTP-API client with all configuration options.
     *
     * @param httpClient the verifying HTTP client (performs verification outside TLS handshake)
     * @param baseUrl the base URL of the remote agent
     * @param timeout the request timeout
     * @param httpAuthHeadersProvider the authentication provider (may be null)
     * @param executor the executor for async operations
     */
    public HttpApiClient(AnsHttpClient httpClient, String baseUrl, Duration timeout,
                         HttpAuthHeadersProvider httpAuthHeadersProvider, Executor executor) {
        this.httpClient = Objects.requireNonNull(httpClient, "HTTP client cannot be null");
        this.baseUrl = normalizeBaseUrl(Objects.requireNonNull(baseUrl, "Base URL cannot be null"));
        this.timeout = Objects.requireNonNull(timeout, "Timeout cannot be null");
        this.httpAuthHeadersProvider = httpAuthHeadersProvider;
        this.executor = Objects.requireNonNull(executor, "Executor cannot be null");

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    // ==================== GET Operations ====================

    /**
     * Sends a GET request and returns the response as string.
     *
     * @param path the request path
     * @return the response body as string
     */
    public String get(String path) {
        HttpRequest request = buildRequest("GET", path)
            .GET()
            .build();

        return sendRequest(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Sends a GET request and deserializes the response.
     *
     * @param path the request path
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return the deserialized response
     */
    public <T> T get(String path, Class<T> responseType) {
        HttpRequest request = buildRequest("GET", path)
            .GET()
            .build();

        return sendTypedRequest(request, responseType);
    }

    /**
     * Sends a GET request asynchronously.
     *
     * @param path the request path
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return a CompletableFuture with the deserialized response
     */
    public <T> CompletableFuture<T> getAsync(String path, Class<T> responseType) {
        return CompletableFuture.supplyAsync(() -> get(path, responseType), executor);
    }

    // ==================== POST Operations ====================

    /**
     * Sends a POST request with JSON body.
     *
     * @param path the request path
     * @param body the request body (will be serialized to JSON)
     * @return the response body as string
     */
    public String post(String path, Object body) {
        String jsonBody = serialize(body);

        HttpRequest request = buildRequest("POST", path)
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        return sendRequest(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Sends a POST request and deserializes the response.
     *
     * @param path the request path
     * @param body the request body
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return the deserialized response
     */
    public <T> T post(String path, Object body, Class<T> responseType) {
        String jsonBody = serialize(body);

        HttpRequest request = buildRequest("POST", path)
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        return sendTypedRequest(request, responseType);
    }

    /**
     * Sends a POST request asynchronously.
     *
     * @param path the request path
     * @param body the request body
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return a CompletableFuture with the deserialized response
     */
    public <T> CompletableFuture<T> postAsync(String path, Object body, Class<T> responseType) {
        return CompletableFuture.supplyAsync(() -> post(path, body, responseType), executor);
    }

    // ==================== PUT Operations ====================

    /**
     * Sends a PUT request with JSON body.
     *
     * @param path the request path
     * @param body the request body
     * @return the response body as string
     */
    public String put(String path, Object body) {
        String jsonBody = serialize(body);

        HttpRequest request = buildRequest("PUT", path)
            .PUT(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        return sendRequest(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Sends a PUT request and deserializes the response.
     *
     * @param path the request path
     * @param body the request body
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return the deserialized response
     */
    public <T> T put(String path, Object body, Class<T> responseType) {
        String jsonBody = serialize(body);

        HttpRequest request = buildRequest("PUT", path)
            .PUT(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        return sendTypedRequest(request, responseType);
    }

    // ==================== DELETE Operations ====================

    /**
     * Sends a DELETE request.
     *
     * @param path the request path
     * @return the response body as string
     */
    public String delete(String path) {
        HttpRequest request = buildRequest("DELETE", path)
            .DELETE()
            .build();

        return sendRequest(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Sends a DELETE request and deserializes the response.
     *
     * @param path the request path
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return the deserialized response
     */
    public <T> T delete(String path, Class<T> responseType) {
        HttpRequest request = buildRequest("DELETE", path)
            .DELETE()
            .build();

        return sendTypedRequest(request, responseType);
    }

    // ==================== Raw Request ====================

    /**
     * Sends a custom HTTP request.
     *
     * @param method the HTTP method
     * @param path the request path
     * @param body the request body (null for no body)
     * @param headers additional headers
     * @return the response body as string
     */
    public String request(String method, String path, String body, Map<String, String> headers) {
        URI uri = buildUri(path);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json");

        // Apply auth headers if configured - use the richer method with request context
        if (httpAuthHeadersProvider != null) {
            httpAuthHeadersProvider.getHeaders(method, uri).forEach(builder::header);
        }

        // Apply custom headers (after auth headers, so they can override if needed)
        if (headers != null) {
            headers.forEach(builder::header);
        }

        HttpRequest.BodyPublisher bodyPublisher = body != null
                ? HttpRequest.BodyPublishers.ofString(body)
                : HttpRequest.BodyPublishers.noBody();

        HttpRequest request = builder
                .method(method, bodyPublisher)
                .build();

        return sendRequest(request, HttpResponse.BodyHandlers.ofString());
    }

    // ==================== Private Methods ====================

    private HttpRequest.Builder buildRequest(String method, String path) {
        URI uri = buildUri(path);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json");

        // Apply auth headers if configured - use the richer method with request context
        if (httpAuthHeadersProvider != null) {
            httpAuthHeadersProvider.getHeaders(method, uri).forEach(builder::header);
        }

        return builder;
    }

    private URI buildUri(String path) {
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        return URI.create(baseUrl + normalizedPath);
    }

    /**
     * Sends a request and deserializes the response to the specified type.
     *
     * <p>This method reads the response body as a string first, checks the status code,
     * and only then deserializes on success. This ensures error responses preserve the
     * API error message rather than failing with deserialization errors.</p>
     *
     * @param request the HTTP request to send
     * @param responseType the class to deserialize the response to
     * @param <T> the response type
     * @return the deserialized response
     */
    private <T> T sendTypedRequest(HttpRequest request, Class<T> responseType) {
        LOGGER.debug("Sending {} request to {}", request.method(), request.uri());

        try {
            // Read body as string first to check status before deserializing
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();
            String responseBody = response.body();

            LOGGER.debug("Received {} response from {}", statusCode, request.uri());

            // Check for error status codes BEFORE deserializing
            if (statusCode < 200 || statusCode >= 300) {
                String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
                handleErrors(statusCode, responseBody != null ? responseBody : "", requestId);
            }

            // Deserialize only on success
            return deserializeFromString(responseBody, responseType);

        } catch (IOException e) {
            throw new AgentConnectionException(
                    "Network error while communicating with agent: " + e.getMessage(),
                    e,
                    baseUrl
            );
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AgentConnectionException(
                    "Request interrupted",
                    e,
                    baseUrl
            );
        }
    }

    /**
     * Sends a request with the specified body handler.
     *
     * <p>This is the core method that handles all HTTP communication, error handling,
     * and exception wrapping. All public methods delegate to this.</p>
     *
     * @param request the HTTP request to send
     * @param bodyHandler the body handler for processing the response
     * @param <T> the response type
     * @return the response body
     */
    private <T> T sendRequest(HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
        LOGGER.debug("Sending {} request to {}", request.method(), request.uri());

        try {
            HttpResponse<T> response = httpClient.send(request, bodyHandler);
            int statusCode = response.statusCode();

            LOGGER.debug("Received {} response from {}", statusCode, request.uri());

            // Check for error status codes
            if (statusCode < 200 || statusCode >= 300) {
                String requestId = response.headers().firstValue("X-Request-Id").orElse(null);
                // Body is already read by the body handler, convert to string for error message
                String errorBody = response.body() != null ? response.body().toString() : "";
                handleErrors(statusCode, errorBody, requestId);
            }

            return response.body();

        } catch (IOException e) {
            throw new AgentConnectionException(
                    "Network error while communicating with agent: " + e.getMessage(),
                    e,
                    baseUrl
            );
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AgentConnectionException(
                    "Request interrupted",
                    e,
                    baseUrl
            );
        }
    }

    /**
     * Deserializes JSON from a string.
     */
    private <T> T deserializeFromString(String json, Class<T> type) {
        try {
            return objectMapper.readValue(json, type);
        } catch (IOException e) {
            throw new ProtocolException(
                    "Failed to deserialize response: " + e.getMessage(),
                    e,
                    PROTOCOL_NAME,
                    0,
                    null
            );
        }
    }

    private static void handleErrors(int statusCode, String body, String requestId) {
        if (statusCode == 401 || statusCode == 403) {
            throw new ProtocolException(
                "Authentication/authorization failed: " + body,
                null,
                PROTOCOL_NAME,
                    statusCode,
                    requestId
            );
        }

        if (statusCode == 404) {
            throw new ProtocolException(
                "Resource not found: " + body,
                null,
                PROTOCOL_NAME,
                    statusCode,
                    requestId
            );
        }

        throw new ProtocolException(
            "Request failed with status " + statusCode + ": " + body,
            null,
            PROTOCOL_NAME,
                statusCode,
                requestId
        );
    }

    private String serialize(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new ProtocolException(
                "Failed to serialize request body: " + e.getMessage(),
                e,
                PROTOCOL_NAME,
                0,
                null
            );
        }
    }

    private static String normalizeBaseUrl(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * Returns the base URL.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Returns the configured timeout.
     *
     * @return the timeout
     */
    public Duration getTimeout() {
        return timeout;
    }
}