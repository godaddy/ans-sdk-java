package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.exception.VerificationException;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * An HttpClient wrapper that performs verification outside the TLS handshake.
 *
 * <p>This wrapper orchestrates the pre-flight verification pattern:</p>
 * <ol>
 *   <li><b>Pre-verify</b> (cached): Look up DANE/Badge expectations</li>
 *   <li><b>TLS handshake</b>: PKI-only validation via delegate HttpClient</li>
 *   <li><b>Capture cert</b>: Extract server certificate from handshake</li>
 *   <li><b>Post-verify</b>: Compare actual cert to expectations</li>
 *   <li><b>Return response</b>: If verification passes</li>
 * </ol>
 *
 * <h2>Cache Staleness Handling</h2>
 * <p>If a fingerprint mismatch occurs (e.g., agent rotated its certificate since
 * the pre-verification was cached), this client automatically:</p>
 * <ol>
 *   <li>Invalidates the cached pre-verification data</li>
 *   <li>Fetches fresh data from the transparency log</li>
 *   <li>Retries verification with the fresh data</li>
 *   <li>Only fails if the retry also produces a mismatch</li>
 * </ol>
 *
 * <h2>Benefits</h2>
 * <ul>
 *   <li>TLS handshake is fast (PKI only)</li>
 *   <li>Pre-verification results are cached</li>
 *   <li>Async pre-verification is possible</li>
 *   <li>Clear separation of TLS and verification</li>
 *   <li>Automatic retry on cache staleness</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * AnsHttpClient client = AnsHttpClient.builder()
 *     .delegate(httpClient)
 *     .connectionVerifier(verifier)
 *     .verificationPolicy(VerificationPolicy.DANE_REQUIRED)
 *     .build();
 *
 * HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
 * }</pre>
 */
public class AnsHttpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnsHttpClient.class);
    private static final Duration DEFAULT_PRE_VERIFY_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration CACHE_TTL = Duration.ofMinutes(15);

    private final HttpClient delegate;
    private final ConnectionVerifier verifier;
    private final VerificationPolicy policy;
    private final Duration preVerifyTimeout;

    // Cache for pre-verification results
    private final Map<String, CachedPreVerification> preVerifyCache = new ConcurrentHashMap<>();

    private AnsHttpClient(Builder builder) {
        this.delegate = Objects.requireNonNull(builder.delegate, "Delegate HttpClient cannot be null");
        this.verifier = Objects.requireNonNull(builder.verifier, "ConnectionVerifier cannot be null");
        this.policy = Objects.requireNonNull(builder.policy, "VerificationPolicy cannot be null");
        this.preVerifyTimeout = builder.preVerifyTimeout != null
            ? builder.preVerifyTimeout
            : DEFAULT_PRE_VERIFY_TIMEOUT;
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a AnsHttpClient that performs no verification.
     *
     * <p>This is useful for testing or when verification is handled elsewhere.
     * All requests are passed directly to the delegate HttpClient without
     * any pre/post verification.</p>
     *
     * @param httpClient the underlying HttpClient
     * @return a AnsHttpClient that bypasses verification
     */
    public static AnsHttpClient noVerification(HttpClient httpClient) {
        return new NoVerificationHttpClient(httpClient);
    }

    /**
     * Internal implementation that bypasses verification.
     */
    private static class NoVerificationHttpClient extends AnsHttpClient {
        private final HttpClient delegate;

        NoVerificationHttpClient(HttpClient delegate) {
            super(createNoOpBuilder(delegate));
            this.delegate = delegate;
        }

        private static Builder createNoOpBuilder(HttpClient delegate) {
            return builder()
                .delegate(delegate)
                .connectionVerifier(new NoOpConnectionVerifier())
                .verificationPolicy(VerificationPolicy.PKI_ONLY);
        }

        @Override
        public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
                throws IOException, InterruptedException {
            return delegate.send(request, responseBodyHandler);
        }

        @Override
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                                  HttpResponse.BodyHandler<T> responseBodyHandler) {
            return delegate.sendAsync(request, responseBodyHandler);
        }

        @Override
        public HttpClient getDelegate() {
            return delegate;
        }
    }

    /**
     * Sends an HTTP request with verification.
     *
     * @param request the HTTP request
     * @param responseBodyHandler the response body handler
     * @param <T> the response body type
     * @return the HTTP response
     * @throws IOException if an I/O error occurs
     * @throws InterruptedException if the operation is interrupted
     * @throws VerificationException if post-handshake verification fails
     */
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {

        URI uri = request.uri();
        String hostname = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : 443;

        LOGGER.debug("Sending request to {}:{} with verification", hostname, port);

        // 1. Pre-verify (uses cache)
        PreVerificationResult preResult = getOrPreVerify(hostname, port);

        // Check if badge pre-verification failed and badge is REQUIRED
        if (preResult.badgePreVerifyFailed() && policy.badgeMode() == VerificationMode.REQUIRED) {
            LOGGER.error("Badge pre-verification failed for {} and is REQUIRED: {}",
                hostname, preResult.badgeFailureReason());
            throw new VerificationException(
                VerificationResult.error(
                    VerificationResult.VerificationType.BADGE,
                    preResult.badgeFailureReason() != null
                        ? preResult.badgeFailureReason()
                        : "Badge pre-verification failed"),
                hostname);
        }

        // 2. Send request (TLS handshake with PKI only)
        HttpResponse<T> response = delegate.send(request, responseBodyHandler);

        // 3. Get captured certificate by hostname
        X509Certificate[] capturedCerts = CertificateCapturingTrustManager.getCapturedCertificates(hostname);
        try {
            if (capturedCerts == null || capturedCerts.length == 0) {
                LOGGER.warn("No certificates captured during TLS handshake for {}", hostname);
                // Can't verify without certificate - decide based on policy
                if (policy.hasAnyVerification()) {
                    throw new VerificationException(
                        VerificationResult.error(
                            VerificationResult.VerificationType.DANE,
                            "No certificates captured during TLS handshake"),
                        hostname);
                }
                return response;
            }

            X509Certificate serverCert = capturedCerts[0];

            // 4. Post-verify
            List<VerificationResult> results = verifier.postVerify(hostname, serverCert, preResult);
            VerificationResult combined = verifier.combine(results, policy);

            if (combined.shouldFail()) {
                // 5. On fingerprint mismatch, retry with fresh data (cache may be stale)
                if (isFingerprintMismatch(combined)) {
                    LOGGER.info("Fingerprint mismatch for {} - retrying with fresh data", hostname);
                    VerificationResult retryResult = retryWithFreshData(hostname, port, serverCert);
                    if (retryResult.shouldFail()) {
                        LOGGER.error("Verification failed after retry for {}: {}", hostname, retryResult);
                        throw new VerificationException(retryResult, hostname);
                    }
                    LOGGER.debug("Verification successful after retry for {}", hostname);
                    return response;
                }

                LOGGER.error("Post-handshake verification failed for {}: {}", hostname, combined);
                throw new VerificationException(combined, hostname);
            }

            LOGGER.debug("Verification successful for {}", hostname);
            return response;

        } finally {
            // Always clear captured certificates to prevent memory leaks
            CertificateCapturingTrustManager.clearCapturedCertificates(hostname);
        }
    }

    /**
     * Sends an HTTP request asynchronously with verification.
     *
     * @param request the HTTP request
     * @param responseBodyHandler the response body handler
     * @param <T> the response body type
     * @return a CompletableFuture for the HTTP response
     */
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> responseBodyHandler) {
        URI uri = request.uri();
        String hostname = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : 443;

        // Pre-verify async, then send
        return preVerifyAsync(hostname, port)
            .thenCompose(preResult -> {
                // Check if badge pre-verification failed and badge is REQUIRED
                if (preResult.badgePreVerifyFailed() && policy.badgeMode() == VerificationMode.REQUIRED) {
                    VerificationResult failResult = VerificationResult.error(
                        VerificationResult.VerificationType.BADGE,
                        preResult.badgeFailureReason() != null
                            ? preResult.badgeFailureReason()
                            : "Badge pre-verification failed");
                    return CompletableFuture.failedFuture(new VerificationException(failResult, hostname));
                }

                return delegate.sendAsync(request, responseBodyHandler)
                    .thenApply(response -> {
                        // Post-verify using hostname-keyed certificate capture
                        X509Certificate[] capturedCerts =
                                CertificateCapturingTrustManager.getCapturedCertificates(hostname);
                        try {
                            if (capturedCerts == null || capturedCerts.length == 0) {
                                if (policy.hasAnyVerification()) {
                                    throw new VerificationException(
                                        VerificationResult.error(
                                            VerificationResult.VerificationType.DANE,
                                            "No certificates captured during TLS handshake"),
                                        hostname);
                                }
                                return response;
                            }

                            X509Certificate serverCert = capturedCerts[0];
                            List<VerificationResult> results = verifier.postVerify(
                                hostname, serverCert, preResult);
                            VerificationResult combined = verifier.combine(results, policy);

                            if (combined.shouldFail()) {
                                // On fingerprint mismatch, retry with fresh data (cache may be stale)
                                if (isFingerprintMismatch(combined)) {
                                    LOGGER.info("Fingerprint mismatch for {} - retrying with fresh data", hostname);
                                    VerificationResult retryResult = retryWithFreshData(hostname, port, serverCert);
                                    if (retryResult.shouldFail()) {
                                        throw new VerificationException(retryResult, hostname);
                                    }
                                    return response;
                                }
                                throw new VerificationException(combined, hostname);
                            }

                            return response;
                        } finally {
                            CertificateCapturingTrustManager.clearCapturedCertificates(hostname);
                        }
                    });
            });
    }

    /**
     * Returns the underlying HttpClient.
     *
     * @return the delegate HttpClient
     */
    public HttpClient getDelegate() {
        return delegate;
    }

    /**
     * Checks if the verification result is a fingerprint mismatch (vs other failures).
     *
     * <p>Fingerprint mismatches may indicate stale cached data and should trigger
     * a retry with fresh data from the transparency log.</p>
     *
     * @param result the verification result
     * @return true if this is a fingerprint mismatch
     */
    private boolean isFingerprintMismatch(VerificationResult result) {
        return result.status() == VerificationResult.Status.MISMATCH;
    }

    /**
     * Retries verification with fresh data from the transparency log.
     *
     * <p>This is called when a fingerprint mismatch is detected, which may indicate
     * that the cached pre-verification data is stale (e.g., agent rotated its
     * certificate since the cache was populated).</p>
     *
     * @param hostname the hostname to verify
     * @param port the port number
     * @param serverCert the server certificate from the TLS handshake
     * @return the verification result from the retry attempt
     */
    private VerificationResult retryWithFreshData(String hostname, int port, X509Certificate serverCert) {
        // Invalidate cache to force fresh lookup
        invalidateCache(hostname, port);

        // Fetch fresh pre-verification data
        PreVerificationResult freshPreResult = getOrPreVerify(hostname, port);

        // Retry post-verification with fresh data
        List<VerificationResult> results = verifier.postVerify(hostname, serverCert, freshPreResult);
        return verifier.combine(results, policy);
    }

    /**
     * Clears the pre-verification cache.
     */
    public void clearCache() {
        preVerifyCache.clear();
    }

    /**
     * Invalidates cache entry for a specific host.
     *
     * @param hostname the hostname to invalidate
     * @param port the port number
     */
    public void invalidateCache(String hostname, int port) {
        preVerifyCache.remove(cacheKey(hostname, port));
    }

    /**
     * Gets or computes pre-verification result (synchronous).
     */
    private PreVerificationResult getOrPreVerify(String hostname, int port) {
        String key = cacheKey(hostname, port);

        CachedPreVerification cached = preVerifyCache.get(key);
        if (cached != null && !cached.isExpired()) {
            LOGGER.debug("Using cached pre-verification for {}:{}", hostname, port);
            return cached.result();
        }

        LOGGER.debug("Pre-verifying {}:{}", hostname, port);
        try {
            PreVerificationResult result = verifier.preVerify(hostname, port)
                .get(preVerifyTimeout.toMillis(), TimeUnit.MILLISECONDS);

            preVerifyCache.put(key, new CachedPreVerification(result, System.currentTimeMillis()));
            return result;

        } catch (Exception e) {
            LOGGER.warn("Pre-verification failed for {}:{}: {}", hostname, port, e.getMessage());
            // Return empty pre-verification - will rely on policy to decide if this is fatal
            return PreVerificationResult.builder(hostname, port).build();
        }
    }

    /**
     * Pre-verifies asynchronously.
     */
    private CompletableFuture<PreVerificationResult> preVerifyAsync(String hostname, int port) {
        String key = cacheKey(hostname, port);

        CachedPreVerification cached = preVerifyCache.get(key);
        if (cached != null && !cached.isExpired()) {
            LOGGER.debug("Using cached pre-verification for {}:{}", hostname, port);
            return CompletableFuture.completedFuture(cached.result());
        }

        return verifier.preVerify(hostname, port)
            .orTimeout(preVerifyTimeout.toMillis(), TimeUnit.MILLISECONDS)
            .thenApply(result -> {
                preVerifyCache.put(key, new CachedPreVerification(result, System.currentTimeMillis()));
                return result;
            })
            .exceptionally(e -> {
                LOGGER.warn("Pre-verification failed for {}:{}: {}", hostname, port, e.getMessage());
                return PreVerificationResult.builder(hostname, port).build();
            });
    }

    private String cacheKey(String hostname, int port) {
        return hostname + ":" + port;
    }

    /**
     * Cached pre-verification result with timestamp.
     */
    private record CachedPreVerification(PreVerificationResult result, long timestamp) {
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL.toMillis();
        }
    }

    /**
     * Builder for AnsHttpClient.
     */
    public static class Builder {
        private HttpClient delegate;
        private ConnectionVerifier verifier;
        private VerificationPolicy policy;
        private Duration preVerifyTimeout;

        private Builder() {
        }

        /**
         * Sets the delegate HttpClient.
         *
         * <p>The delegate should be configured with PKI-only SSL (using
         * {@link CertificateCapturingTrustManager}).</p>
         *
         * @param delegate the delegate HttpClient
         * @return this builder
         */
        public Builder delegate(HttpClient delegate) {
            this.delegate = delegate;
            return this;
        }

        /**
         * Sets the connection verifier.
         *
         * @param verifier the connection verifier
         * @return this builder
         */
        public Builder connectionVerifier(ConnectionVerifier verifier) {
            this.verifier = verifier;
            return this;
        }

        /**
         * Sets the verification policy.
         *
         * @param policy the verification policy
         * @return this builder
         */
        public Builder verificationPolicy(VerificationPolicy policy) {
            this.policy = policy;
            return this;
        }

        /**
         * Sets the pre-verification timeout.
         *
         * @param timeout the timeout for pre-verification
         * @return this builder
         */
        public Builder preVerifyTimeout(Duration timeout) {
            this.preVerifyTimeout = timeout;
            return this;
        }

        /**
         * Builds the AnsHttpClient.
         *
         * @return the built client
         */
        public AnsHttpClient build() {
            return new AnsHttpClient(this);
        }
    }
}
