package com.godaddy.ans.sdk.agent.http.auth;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Provides authentication headers for HTTP requests.
 *
 * <p>Implementations should be thread-safe, as they may be called concurrently
 * from multiple transports.</p>
 *
 * <h2>Built-in Providers</h2>
 *
 * <h3>Bearer Token</h3>
 * <pre>{@code
 * HttpAuthHeadersProvider auth = HttpAuthHeadersProvider.bearer("eyJhbGciOiJSUzI1NiIs...");
 * // Adds: Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
 * }</pre>
 *
 * <h3>API Key (sso-key format)</h3>
 * <pre>{@code
 * HttpAuthHeadersProvider auth = HttpAuthHeadersProvider.apiKey("my-key", "my-secret");
 * // Adds: Authorization: sso-key my-key:my-secret
 * }</pre>
 *
 * <h3>Custom Header</h3>
 * <pre>{@code
 * HttpAuthHeadersProvider auth = HttpAuthHeadersProvider.header("X-Custom-Auth", "my-value");
 * // Adds: X-Custom-Auth: my-value
 * }</pre>
 *
 * <h3>Multiple Headers</h3>
 * <pre>{@code
 * HttpAuthHeadersProvider auth = HttpAuthHeadersProvider.headers(Map.of(
 *     "X-Api-Key", "key123",
 *     "X-Tenant-Id", "tenant456"
 * ));
 * }</pre>
 *
 * <h2>Usage with ConnectOptions</h2>
 * <pre>{@code
 * StreamableHttpTransport transport = client.connectStreaming(
 *     "https://agent.example.com/ans",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
 *         .HttpAuthHeadersProvider(HttpAuthHeadersProvider.bearer(token))
 *         .build()
 * );
 * }</pre>
 *
 * @see com.godaddy.ans.sdk.agent.ConnectOptions
 */
@FunctionalInterface
public interface HttpAuthHeadersProvider {

    /**
     * A provider that adds no authentication headers.
     */
    HttpAuthHeadersProvider NONE = () -> Collections.emptyMap();

    /**
     * Returns headers to add to each HTTP request.
     *
     * <p>Called before every request. The returned map should be immutable
     * or the caller should not modify it.</p>
     *
     * @return a map of header names to values (never null, may be empty)
     */
    Map<String, String> getHeaders();

    /**
     * Returns headers for a specific request context.
     *
     * <p>Override this method for request-aware authentication such as
     * request signing.</p>
     *
     * @param method the HTTP method (GET, POST, etc.)
     * @param uri the request URI
     * @return a map of header names to values (never null, may be empty)
     */
    default Map<String, String> getHeaders(String method, URI uri) {
        return getHeaders();
    }

    // ==================== Factory Methods ====================

    /**
     * Creates an HttpAuthHeadersProvider for Bearer token authentication.
     *
     * <p>Adds the header: {@code Authorization: Bearer {token}}</p>
     *
     * @param token the bearer token
     * @return an HttpAuthHeadersProvider that adds a Bearer token header
     * @throws NullPointerException if token is null
     */
    static HttpAuthHeadersProvider bearer(String token) {
        Objects.requireNonNull(token, "Token cannot be null");
        return () -> Map.of("Authorization", "Bearer " + token);
    }

    /**
     * Creates an HttpAuthHeadersProvider for API key authentication (sso-key format).
     *
     * <p>Adds the header: {@code Authorization: sso-key {key}:{secret}}</p>
     *
     * @param key the API key
     * @param secret the API secret
     * @return an HttpAuthHeadersProvider that adds an sso-key header
     * @throws NullPointerException if key or secret is null
     */
    static HttpAuthHeadersProvider apiKey(String key, String secret) {
        Objects.requireNonNull(key, "Key cannot be null");
        Objects.requireNonNull(secret, "Secret cannot be null");
        return () -> Map.of("Authorization", "sso-key " + key + ":" + secret);
    }

    /**
     * Creates an HttpAuthHeadersProvider for a single custom header.
     *
     * @param name the header name
     * @param value the header value
     * @return an HttpAuthHeadersProvider that adds the specified header
     * @throws NullPointerException if name or value is null
     */
    static HttpAuthHeadersProvider header(String name, String value) {
        Objects.requireNonNull(name, "Header name cannot be null");
        Objects.requireNonNull(value, "Header value cannot be null");
        return () -> Map.of(name, value);
    }

    /**
     * Creates an HttpAuthHeadersProvider for multiple custom headers.
     *
     * @param headers the headers to add
     * @return an HttpAuthHeadersProvider that adds the specified headers
     * @throws NullPointerException if headers is null
     */
    static HttpAuthHeadersProvider headers(Map<String, String> headers) {
        Objects.requireNonNull(headers, "Headers cannot be null");
        // Defensive copy to ensure immutability
        Map<String, String> copy = Map.copyOf(headers);
        return () -> copy;
    }
}
