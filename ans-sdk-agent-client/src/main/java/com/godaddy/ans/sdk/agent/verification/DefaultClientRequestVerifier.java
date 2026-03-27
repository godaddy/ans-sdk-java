package com.godaddy.ans.sdk.agent.verification;

import static com.godaddy.ans.sdk.crypto.CertificateUtils.normalizeFingerprint;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.DefaultScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.DefaultScittVerifier;
import com.godaddy.ans.sdk.transparency.scitt.ScittExpectation;
import com.godaddy.ans.sdk.transparency.scitt.ScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.ScittHeaders;
import com.godaddy.ans.sdk.transparency.scitt.ScittReceipt;
import com.godaddy.ans.sdk.transparency.scitt.ScittVerifier;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

/**
 * Default implementation of {@link ClientRequestVerifier}.
 *
 * <p>This verifier extracts SCITT artifacts from request headers, verifies their
 * cryptographic signatures, and matches the client certificate fingerprint against
 * the identity certificate fingerprints in the status token.</p>
 *
 * <h2>Key Design Decisions</h2>
 * <ul>
 *   <li><b>Identity vs Server Certs:</b> Uses {@code validIdentityCertFingerprints()}
 *       for client verification, NOT {@code validServerCertFingerprints()}. Identity
 *       certs identify the agent, server certs are for TLS endpoints.</li>
 *   <li><b>Caching:</b> Results are cached by (receipt hash, token hash, cert fingerprint)
 *       to avoid redundant verification for repeated requests.</li>
 *   <li><b>Security:</b> Uses constant-time comparison for fingerprint matching.</li>
 * </ul>
 *
 * @see ClientRequestVerifier
 */
public class DefaultClientRequestVerifier implements ClientRequestVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultClientRequestVerifier.class);

    /**
     * Maximum header size in bytes to prevent DoS attacks.
     */
    private static final int MAX_HEADER_SIZE = 64 * 1024; // 64KB

    /**
     * Maximum cache size to prevent memory exhaustion DoS through cache flooding.
     */
    private static final int MAX_CACHE_SIZE = 1000;

    private final TransparencyClient transparencyClient;
    private final ScittVerifier scittVerifier;
    private final ScittHeaderProvider headerProvider;
    private final Executor executor;
    private final Duration cacheTtl;

    // Verification result cache keyed by (receiptHash:tokenHash:certFingerprint)
    // Caffeine handles automatic eviction and size limits
    private final Cache<String, CachedResult> verificationCache;

    private DefaultClientRequestVerifier(Builder builder) {
        this.transparencyClient = builder.transparencyClient;
        this.scittVerifier = builder.scittVerifier;
        this.headerProvider = builder.headerProvider;
        this.executor = builder.executor;
        this.cacheTtl = builder.cacheTtl;

        // Build cache with custom expiry based on min(cacheTtl, tokenExpiry)
        this.verificationCache = Caffeine.newBuilder()
            .maximumSize(MAX_CACHE_SIZE)
            .expireAfter(new VerificationResultExpiry())
            .build();
    }

    @Override
    public CompletableFuture<ClientRequestVerificationResult> verify(
            X509Certificate clientCert,
            Map<String, String> requestHeaders,
            VerificationPolicy policy) {

        Objects.requireNonNull(clientCert, "clientCert cannot be null");
        Objects.requireNonNull(requestHeaders, "requestHeaders cannot be null");
        Objects.requireNonNull(policy, "policy cannot be null");

        long startNanos = System.nanoTime();

        // Steps 1-4 are synchronous (header validation, extraction, cache check)
        // Step 5 (SCITT verification) is async due to getRootKeyAsync()
        // Step 6 (fingerprint match) chains after Step 5

        try {
            // Step 1-3: Validate headers and extract artifacts (synchronous)
            ArtifactExtractionResult extractionResult = extractAndValidateArtifacts(
                requestHeaders, policy, clientCert, startNanos);
            if (extractionResult.failure != null) {
                return CompletableFuture.completedFuture(extractionResult.failure);
            }

            ScittHeaderProvider.ScittArtifacts artifacts = extractionResult.artifacts;
            ScittReceipt receipt = artifacts.receipt();
            StatusToken statusToken = artifacts.statusToken();

            // Step 4: Check cache (synchronous)
            // Use raw header values for cache key - avoids 2x SHA-256 on every lookup
            String receiptHeader = requestHeaders.get(ScittHeaders.SCITT_RECEIPT_HEADER);
            String tokenHeader = requestHeaders.get(ScittHeaders.STATUS_TOKEN_HEADER);
            String clientFingerprint = CertificateUtils.computeSha256Fingerprint(clientCert);
            String cacheKey = computeCacheKey(receiptHeader, tokenHeader, clientFingerprint);
            ClientRequestVerificationResult cachedResult = checkCache(cacheKey);
            if (cachedResult != null) {
                return CompletableFuture.completedFuture(cachedResult);
            }

            // Step 5: Verify SCITT artifacts asynchronously (uses getRootKeyAsync)
            return verifyScittArtifactsAsync(receipt, statusToken, policy, clientCert, startNanos)
                .thenApplyAsync(scittResult -> {
                    if (scittResult.failure != null) {
                        return scittResult.failure;
                    }

                    // Step 6: Verify fingerprint match
                    ClientRequestVerificationResult fingerprintResult = verifyFingerprintMatch(
                        clientFingerprint, scittResult.expectation, statusToken, receipt,
                        clientCert, policy, startNanos);
                    if (fingerprintResult != null) {
                        return fingerprintResult;
                    }

                    // Success - create result and cache it
                    return createSuccessResult(statusToken, receipt, clientCert, policy, startNanos, cacheKey);
                }, executor)
                .exceptionally(e -> {
                    Throwable cause = e instanceof CompletionException && e.getCause() != null
                        ? e.getCause() : e;
                    LOGGER.error("Unexpected error during client verification", cause);
                    return ClientRequestVerificationResult.failure(
                        "Verification error: " + cause.getMessage(),
                        clientCert,
                        policy,
                        durationSinceNanos(startNanos)
                    );
                });
        } catch (Exception e) {
            LOGGER.error("Unexpected error during client verification setup", e);
            return CompletableFuture.completedFuture(ClientRequestVerificationResult.failure(
                "Verification error: " + e.getMessage(),
                clientCert,
                policy,
                durationSinceNanos(startNanos)
            ));
        }
    }

    // ==================== Artifact Extraction (Steps 1-3) ====================

    /**
     * Result of artifact extraction - either artifacts or a failure.
     */
    private record ArtifactExtractionResult(
        ScittHeaderProvider.ScittArtifacts artifacts,
        ClientRequestVerificationResult failure
    ) {
        static ArtifactExtractionResult success(ScittHeaderProvider.ScittArtifacts artifacts) {
            return new ArtifactExtractionResult(artifacts, null);
        }

        static ArtifactExtractionResult failure(ClientRequestVerificationResult failure) {
            return new ArtifactExtractionResult(null, failure);
        }
    }

    /**
     * Validates headers and extracts SCITT artifacts (Steps 1-3).
     */
    private ArtifactExtractionResult extractAndValidateArtifacts(
            Map<String, String> requestHeaders,
            VerificationPolicy policy,
            X509Certificate clientCert,
            long startNanos) {

        // Step 1: Check header size limits
        String oversizedHeader = checkHeaderSizeLimits(requestHeaders);
        if (oversizedHeader != null) {
            return ArtifactExtractionResult.failure(failureResult(
                "SCITT header exceeds size limit: " + oversizedHeader, clientCert, policy, startNanos));
        }

        // Step 2: Extract SCITT artifacts from headers
        Optional<ScittHeaderProvider.ScittArtifacts> artifactsOpt;
        try {
            artifactsOpt = headerProvider.extractArtifacts(requestHeaders);
        } catch (Exception e) {
            LOGGER.warn("Failed to extract SCITT artifacts: {}", e.getMessage());
            String message = policy.scittMode() == VerificationMode.REQUIRED
                ? "Failed to parse SCITT headers: " + e.getMessage()
                : "SCITT headers invalid (advisory mode)";
            return ArtifactExtractionResult.failure(failureResult(message, clientCert, policy, startNanos));
        }

        // Step 3: Handle missing SCITT artifacts
        if (artifactsOpt.isEmpty() || !artifactsOpt.get().isPresent()) {
            String message = policy.scittMode() == VerificationMode.REQUIRED
                ? "SCITT headers required but not present"
                : "SCITT headers not present";
            if (policy.scittMode() != VerificationMode.REQUIRED) {
                LOGGER.debug("SCITT headers not present, mode={}", policy.scittMode());
            }
            return ArtifactExtractionResult.failure(failureResult(message, clientCert, policy, startNanos));
        }

        return ArtifactExtractionResult.success(artifactsOpt.get());
    }

    // ==================== Cache Check (Step 4) ====================

    /**
     * Checks the cache for a valid cached result.
     *
     * <p>Caffeine automatically handles expiration, so we just need to check if present.</p>
     *
     * @return the cached result if valid, null if cache miss or expired
     */
    private ClientRequestVerificationResult checkCache(String cacheKey) {
        CachedResult cached = verificationCache.getIfPresent(cacheKey);
        if (cached != null) {
            LOGGER.debug("Cache hit for client verification");
            return cached.result();
        }
        return null;
    }

    // ==================== SCITT Verification (Step 5) ====================

    /**
     * Result of SCITT verification - either expectation or a failure.
     */
    private record ScittVerificationResult(
        ScittExpectation expectation,
        ClientRequestVerificationResult failure
    ) {
        static ScittVerificationResult success(ScittExpectation expectation) {
            return new ScittVerificationResult(expectation, null);
        }

        static ScittVerificationResult failure(ClientRequestVerificationResult failure) {
            return new ScittVerificationResult(null, failure);
        }
    }

    /**
     * Verifies SCITT artifacts asynchronously - signatures, Merkle proof, expiry (Step 5).
     *
     * <p>Uses {@link TransparencyClient#getRootKeyAsync()} to avoid blocking the shared
     * thread pool on network I/O during cache misses.</p>
     */
    private CompletableFuture<ScittVerificationResult> verifyScittArtifactsAsync(
            ScittReceipt receipt,
            StatusToken statusToken,
            VerificationPolicy policy,
            X509Certificate clientCert,
            long startNanos) {

        // Validate required artifacts are present (synchronous check)
        List<String> errors = new ArrayList<>();
        if (statusToken == null) {
            errors.add("Status token is required but not present");
        }
        if (receipt == null && policy.scittMode() == VerificationMode.REQUIRED) {
            errors.add("Receipt is required but not present");
        }
        if (!errors.isEmpty()) {
            return CompletableFuture.completedFuture(ScittVerificationResult.failure(
                ClientRequestVerificationResult.failure(
                    errors, statusToken, receipt, clientCert, policy, durationSinceNanos(startNanos))));
        }

        // Fetch public keys asynchronously to avoid blocking executor threads
        return transparencyClient.getRootKeysAsync()
            .thenApplyAsync((Map<String, PublicKey> rootKeys) -> {
                // Verify signatures
                ScittExpectation expectation = scittVerifier.verify(receipt, statusToken, rootKeys);
                if (!expectation.isVerified()) {
                    LOGGER.warn("SCITT verification failed: {}", expectation.failureReason());
                    return ScittVerificationResult.failure(ClientRequestVerificationResult.failure(
                        List.of("SCITT verification failed: " + expectation.failureReason()),
                        statusToken, receipt, clientCert, policy, durationSinceNanos(startNanos)));
                }
                return ScittVerificationResult.success(expectation);
            }, executor)
            .exceptionally(e -> {
                Throwable cause = e instanceof CompletionException && e.getCause() != null
                    ? e.getCause() : e;
                LOGGER.error("Failed to fetch SCITT public keys: {}", cause.getMessage());
                return ScittVerificationResult.failure(failureResult(
                    "Failed to fetch SCITT public keys: " + cause.getMessage(), clientCert, policy, startNanos));
            });
    }

    // ==================== Fingerprint Verification (Step 6) ====================

    /**
     * Verifies client certificate fingerprint matches identity certs (Step 6).
     *
     * @return failure result if mismatch, null if fingerprint matches
     */
    private ClientRequestVerificationResult verifyFingerprintMatch(
            String clientFingerprint,
            ScittExpectation expectation,
            StatusToken statusToken,
            ScittReceipt receipt,
            X509Certificate clientCert,
            VerificationPolicy policy,
            long startNanos) {

        // CRITICAL: Use validIdentityCertFingerprints, NOT validServerCertFingerprints
        List<String> validIdentityFingerprints = expectation.validIdentityCertFingerprints();

        if (validIdentityFingerprints.isEmpty()) {
            LOGGER.warn("No valid identity certificate fingerprints in status token");
            return failureResult("No valid identity certificates in status token", clientCert, policy, startNanos);
        }

        boolean fingerprintMatches = validIdentityFingerprints.stream()
            .anyMatch(expected -> fingerprintMatchesConstantTime(clientFingerprint, expected));

        if (!fingerprintMatches) {
            LOGGER.warn("Client certificate fingerprint does not match any identity cert in status token");
            return ClientRequestVerificationResult.failure(
                List.of("Client certificate fingerprint mismatch",
                    "Actual: " + truncateFingerprint(clientFingerprint),
                    "Expected one of: " + truncateFingerprints(validIdentityFingerprints)),
                statusToken, receipt, clientCert, policy, durationSinceNanos(startNanos));
        }

        return null; // Fingerprint matches - success
    }

    // ==================== Success Result & Caching ====================

    /**
     * Creates success result and caches it.
     *
     * <p>Caffeine automatically handles size limits and expiration.
     * The custom {@link VerificationResultExpiry} ensures entries expire based on
     * min(cacheTtl, tokenExpiry).</p>
     */
    private ClientRequestVerificationResult createSuccessResult(
            StatusToken statusToken,
            ScittReceipt receipt,
            X509Certificate clientCert,
            VerificationPolicy policy,
            long startNanos,
            String cacheKey) {

        LOGGER.info("Client verification successful for agent: {}", statusToken.agentId());

        ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
            statusToken.agentId(),
            statusToken,
            receipt,
            clientCert,
            policy,
            durationSinceNanos(startNanos)
        );

        // Cache the result with token expiry for custom Expiry calculation
        verificationCache.put(cacheKey, new CachedResult(result, statusToken.expiresAt()));

        return result;
    }

    // ==================== Helper Methods ====================

    /**
     * Creates a simple failure result with duration calculation.
     */
    private ClientRequestVerificationResult failureResult(
            String message,
            X509Certificate clientCert,
            VerificationPolicy policy,
            long startNanos) {
        return ClientRequestVerificationResult.failure(message, clientCert, policy, durationSinceNanos(startNanos));
    }

    /**
     * Calculates duration since start time using nanosecond precision.
     *
     * <p>Uses {@link System#nanoTime()} which is more efficient than {@link java.time.Instant#now()}
     * for elapsed time measurement - no object allocation until Duration is created, and it's
     * monotonic (not affected by clock adjustments).</p>
     */
    private Duration durationSinceNanos(long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos);
    }

    /**
     * Checks header size limits to prevent DoS attacks.
     *
     * @return the name of the oversized header, or null if all are within limits
     */
    private String checkHeaderSizeLimits(Map<String, String> headers) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key != null && matchesScittHeaders(key.toLowerCase())) {
                if (value != null && value.length() > MAX_HEADER_SIZE) {
                    return key;
                }
            }
        }
        return null;
    }

    private boolean matchesScittHeaders(String lowerKey) {
        return lowerKey.equals(ScittHeaders.SCITT_RECEIPT_HEADER) ||
                lowerKey.equals(ScittHeaders.STATUS_TOKEN_HEADER);
    }

    /**
     * Computes a cache key from the raw header values and certificate fingerprint.
     *
     * <p>Uses the raw Base64 header strings directly rather than hashing decoded bytes,
     * avoiding 2x SHA-256 computations on every cache lookup.</p>
     */
    private String computeCacheKey(String receiptHeader, String tokenHeader, String certFingerprint) {
        // Use raw Base64 header values directly - they're already unique identifiers
        String receiptKey = receiptHeader != null ? receiptHeader : "none";
        String tokenKey = tokenHeader != null ? tokenHeader : "none";
        return receiptKey + ":" + tokenKey + ":" + certFingerprint;
    }


    /**
     * Constant-time fingerprint comparison to prevent timing attacks.
     */
    private boolean fingerprintMatchesConstantTime(String actual, String expected) {
        if (actual == null || expected == null) {
            return false;
        }
        // Normalize fingerprints
        String normalizedActual = normalizeFingerprint(actual);
        String normalizedExpected = normalizeFingerprint(expected);
        if (normalizedActual.length() != normalizedExpected.length()) {
            return false;
        }
        // Use MessageDigest.isEqual for constant-time comparison
        return MessageDigest.isEqual(
            normalizedActual.getBytes(),
            normalizedExpected.getBytes()
        );
    }

    private String truncateFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.length() <= 16) {
            return fingerprint;
        }
        return fingerprint.substring(0, 16) + "...";
    }

    private String truncateFingerprints(List<String> fingerprints) {
        if (fingerprints.size() <= 2) {
            return fingerprints.stream()
                .map(this::truncateFingerprint)
                .toList()
                .toString();
        }
        return "[" + truncateFingerprint(fingerprints.get(0)) + ", ... (" + fingerprints.size() + " total)]";
    }

    // ==================== Caffeine Cache Support ====================

    /**
     * Cached verification result with token expiry time for custom expiration.
     */
    private record CachedResult(ClientRequestVerificationResult result, Instant tokenExpiresAt) { }

    /**
     * Custom Caffeine expiry that uses the earlier of cache TTL or token expiry.
     *
     * <p>This ensures cached results are never returned after the underlying
     * token has expired, even if the cache TTL hasn't been reached.</p>
     */
    private class VerificationResultExpiry implements Expiry<String, CachedResult> {

        @Override
        public long expireAfterCreate(String key, CachedResult value, long currentTime) {
            long cacheTtlNanos = cacheTtl.toNanos();

            // If token has no expiry, use cache TTL
            if (value.tokenExpiresAt() == null) {
                return cacheTtlNanos;
            }

            // Use min(cacheTtl, tokenRemainingTime)
            Duration tokenRemaining = Duration.between(Instant.now(), value.tokenExpiresAt());
            if (tokenRemaining.isNegative() || tokenRemaining.isZero()) {
                return 0; // Already expired
            }

            return Math.min(cacheTtlNanos, tokenRemaining.toNanos());
        }

        @Override
        public long expireAfterUpdate(String key, CachedResult value, long currentTime, long currentDuration) {
            return expireAfterCreate(key, value, currentTime);
        }

        @Override
        public long expireAfterRead(String key, CachedResult value, long currentTime, long currentDuration) {
            return currentDuration; // No change on read
        }
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for DefaultClientRequestVerifier.
     */
    public static class Builder {
        private TransparencyClient transparencyClient;
        private ScittVerifier scittVerifier;
        private ScittHeaderProvider headerProvider;
        private Executor executor = AnsExecutors.sharedIoExecutor();
        private Duration cacheTtl = Duration.ofMinutes(5);

        /**
         * Sets the TransparencyClient for root key fetching.
         *
         * @param transparencyClient the transparency client (required)
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient transparencyClient) {
            this.transparencyClient = transparencyClient;
            return this;
        }

        /**
         * Sets the SCITT verifier.
         *
         * @param scittVerifier the verifier
         * @return this builder
         */
        public Builder scittVerifier(ScittVerifier scittVerifier) {
            this.scittVerifier = scittVerifier;
            return this;
        }

        /**
         * Sets the header provider.
         *
         * @param headerProvider the header provider
         * @return this builder
         */
        public Builder headerProvider(ScittHeaderProvider headerProvider) {
            this.headerProvider = headerProvider;
            return this;
        }

        /**
         * Sets the executor for async operations.
         *
         * @param executor the executor
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = executor;
            return this;
        }

        /**
         * Sets the verification cache TTL.
         *
         * @param ttl the cache TTL (must be positive)
         * @return this builder
         * @throws IllegalArgumentException if ttl is null, zero, or negative
         */
        public Builder verificationCacheTtl(Duration ttl) {
            Objects.requireNonNull(ttl, "ttl cannot be null");
            if (ttl.isZero() || ttl.isNegative()) {
                throw new IllegalArgumentException("cacheTtl must be positive, got: " + ttl);
            }
            this.cacheTtl = ttl;
            return this;
        }

        /**
         * Builds the verifier.
         *
         * @return the configured verifier
         * @throws NullPointerException if transparencyClient is not set
         */
        public DefaultClientRequestVerifier build() {
            Objects.requireNonNull(transparencyClient, "transparencyClient is required");
            if (scittVerifier == null) {
                scittVerifier = new DefaultScittVerifier();
            }
            if (headerProvider == null) {
                headerProvider = new DefaultScittHeaderProvider();
            }
            return new DefaultClientRequestVerifier(this);
        }
    }
}
