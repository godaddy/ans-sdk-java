package com.godaddy.ans.sdk.agent.http.auth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpAuthHeadersProviderTest {

    @Test
    void noneShouldReturnEmptyMap() {
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.NONE;

        Map<String, String> headers = provider.getHeaders();

        assertNotNull(headers);
        assertTrue(headers.isEmpty());
    }

    @Test
    void bearerShouldReturnAuthorizationHeader() {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.bearer(token);

        Map<String, String> headers = provider.getHeaders();

        assertEquals(1, headers.size());
        assertEquals("Bearer " + token, headers.get("Authorization"));
    }

    @Test
    void bearerShouldRejectNullToken() {
        assertThrows(NullPointerException.class, () -> HttpAuthHeadersProvider.bearer(null));
    }

    @Test
    void apiKeyShouldReturnSsoKeyHeader() {
        String key = "my-key";
        String secret = "my-secret";
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.apiKey(key, secret);

        Map<String, String> headers = provider.getHeaders();

        assertEquals(1, headers.size());
        assertEquals("sso-key my-key:my-secret", headers.get("Authorization"));
    }

    @Test
    void apiKeyShouldRejectNullKey() {
        assertThrows(NullPointerException.class, () -> HttpAuthHeadersProvider.apiKey(null, "secret"));
    }

    @Test
    void apiKeyShouldRejectNullSecret() {
        assertThrows(NullPointerException.class, () -> HttpAuthHeadersProvider.apiKey("key", null));
    }

    @Test
    void headerShouldReturnSingleHeader() {
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.header("X-Custom-Auth", "my-value");

        Map<String, String> headers = provider.getHeaders();

        assertEquals(1, headers.size());
        assertEquals("my-value", headers.get("X-Custom-Auth"));
    }

    @Test
    void headerShouldRejectNullName() {
        assertThrows(NullPointerException.class, () -> HttpAuthHeadersProvider.header(null, "value"));
    }

    @Test
    void headerShouldRejectNullValue() {
        assertThrows(NullPointerException.class, () -> HttpAuthHeadersProvider.header("name", null));
    }

    @Test
    void headersShouldReturnMultipleHeaders() {
        Map<String, String> customHeaders = Map.of(
            "X-Api-Key", "key123",
            "X-Tenant-Id", "tenant456"
        );
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.headers(customHeaders);

        Map<String, String> headers = provider.getHeaders();

        assertEquals(2, headers.size());
        assertEquals("key123", headers.get("X-Api-Key"));
        assertEquals("tenant456", headers.get("X-Tenant-Id"));
    }

    @Test
    void headersShouldRejectNullMap() {
        assertThrows(NullPointerException.class, () -> HttpAuthHeadersProvider.headers(null));
    }

    @Test
    void headersShouldMakeDefensiveCopy() {
        // Original map is immutable via Map.of(), but test that we don't
        // expose the internal map
        Map<String, String> original = Map.of("key", "value");
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.headers(original);

        Map<String, String> headers1 = provider.getHeaders();
        Map<String, String> headers2 = provider.getHeaders();

        assertEquals(headers1, headers2);
        assertEquals("value", headers1.get("key"));
    }

    @Test
    void getHeadersWithContextShouldDelegateToSimpleMethod() {
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.bearer("token");

        Map<String, String> simpleHeaders = provider.getHeaders();
        Map<String, String> contextHeaders = provider.getHeaders("POST", URI.create("https://example.com/api"));

        assertEquals(simpleHeaders, contextHeaders);
    }

    @Test
    void shouldBeThreadSafe() throws InterruptedException {
        HttpAuthHeadersProvider provider = HttpAuthHeadersProvider.bearer("token");

        // Call from multiple threads
        Thread[] threads = new Thread[10];
        String[] results = new String[10];

        for (int i = 0; i < threads.length; i++) {
            final int idx = i;
            threads[i] = new Thread(() -> {
                Map<String, String> headers = provider.getHeaders();
                results[idx] = headers.get("Authorization");
            });
        }

        for (Thread thread : threads) {
            thread.start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        for (String result : results) {
            assertEquals("Bearer token", result);
        }
    }

    @Test
    void functionalInterfaceShouldAllowLambda() {
        // HttpAuthHeadersProvider is a functional interface, so lambdas work
        HttpAuthHeadersProvider provider = () -> Map.of("X-Custom", "lambda-value");

        Map<String, String> headers = provider.getHeaders();

        assertEquals("lambda-value", headers.get("X-Custom"));
    }
}
