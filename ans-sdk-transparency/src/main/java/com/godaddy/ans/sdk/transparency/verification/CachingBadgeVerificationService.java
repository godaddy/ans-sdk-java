package com.godaddy.ans.sdk.transparency.verification;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HexFormat;
import java.util.function.Predicate;

/**
 * A caching wrapper for {@link BadgeVerificationService} that reduces blocking
 * during TLS handshakes by caching verification results.
 *
 * <p>This is important because verification happens synchronously during the TLS
 * handshake (in TrustManager callbacks), and involves:</p>
 * <ul>
 *   <li>DNS lookups for _ra-badge records</li>
 *   <li>HTTP calls to the ANS transparency log</li>
 * </ul>
 *
 * <p>By caching results, subsequent connections to the same host or from the same
 * client are much faster.</p>
 *
 * <h2>Cache Keys</h2>
 * <ul>
 *   <li><b>Server verification</b>: hostname</li>
 *   <li><b>Client verification</b>: certificate SHA-256 fingerprint</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * BadgeVerificationService verifier = CachingBadgeVerificationService.builder()
 *     .delegate(BadgeVerificationService.create())
 *     .cacheTtl(Duration.ofMinutes(15))
 *     .build();
 *
 * // First call - makes network requests
 * ServerVerificationResult result1 = verifier.verifyServer("agent.example.com");
 *
 * // Second call - returns cached result
 * ServerVerificationResult result2 = verifier.verifyServer("agent.example.com");
 * }</pre>
 *
 * @see BadgeVerificationService
 */
public final class CachingBadgeVerificationService implements ServerVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(CachingBadgeVerificationService.class);

    private static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(15);
    private static final Duration DEFAULT_NEGATIVE_CACHE_TTL = Duration.ofMinutes(5);
    private static final int DEFAULT_MAX_CACHE_SIZE = 10_000;

    private final BadgeVerificationService delegate;
    private final Cache<String, ServerVerificationResult> serverCache;
    private final Cache<String, ClientVerificationResult> clientCache;

    private CachingBadgeVerificationService(Builder builder) {
        this.delegate = builder.delegate;

        Duration positiveTtl = builder.cacheTtl != null ? builder.cacheTtl : DEFAULT_CACHE_TTL;
        Duration negativeTtl = builder.negativeCacheTtl != null
                ? builder.negativeCacheTtl : DEFAULT_NEGATIVE_CACHE_TTL;

        this.serverCache = Caffeine.newBuilder()
                .maximumSize(DEFAULT_MAX_CACHE_SIZE)
                .expireAfter(new VariableTtlExpiry<>(positiveTtl, negativeTtl, ServerVerificationResult::isSuccess))
                .build();

        this.clientCache = Caffeine.newBuilder()
                .maximumSize(DEFAULT_MAX_CACHE_SIZE)
                .expireAfter(new VariableTtlExpiry<>(positiveTtl, negativeTtl, ClientVerificationResult::isSuccess))
                .build();
    }

    /**
     * Verifies a server against the transparency log, with caching.
     *
     * @param hostname the server hostname to verify
     * @return the verification result (may be cached)
     */
    @Override
    public ServerVerificationResult verifyServer(String hostname) {
        return serverCache.get(hostname, key -> {
            LOG.debug("Cache miss for server verification: {}", key);
            return delegate.verifyServer(key);
        });
    }

    /**
     * Verifies a client certificate against the transparency log, with caching.
     *
     * <p>The cache key is the certificate's SHA-256 fingerprint.</p>
     *
     * @param clientCert the client certificate to verify
     * @return the verification result (may be cached)
     */
    public ClientVerificationResult verifyClient(X509Certificate clientCert) {
        String fingerprint = computeFingerprint(clientCert);
        if (fingerprint == null) {
            // Can't cache without fingerprint - delegate directly
            return delegate.verifyClient(clientCert);
        }

        return clientCache.get(fingerprint, key -> {
            LOG.debug("Cache miss for client verification: {}", truncateFingerprint(key));
            return delegate.verifyClient(clientCert);
        });
    }

    // ==================== Cache Management ====================

    /**
     * Invalidates the cached result for a specific server.
     *
     * @param hostname the hostname to invalidate
     */
    public void invalidateServer(String hostname) {
        serverCache.invalidate(hostname);
        LOG.debug("Invalidated server cache for: {}", hostname);
    }

    /**
     * Invalidates the cached result for a specific client certificate.
     *
     * @param clientCert the certificate to invalidate
     */
    public void invalidateClient(X509Certificate clientCert) {
        String fingerprint = computeFingerprint(clientCert);
        if (fingerprint != null) {
            clientCache.invalidate(fingerprint);
            LOG.debug("Invalidated client cache for: {}", truncateFingerprint(fingerprint));
        }
    }

    /**
     * Clears all cached verification results.
     */
    public void clearCache() {
        long serverCount = serverCache.estimatedSize();
        long clientCount = clientCache.estimatedSize();
        serverCache.invalidateAll();
        clientCache.invalidateAll();
        LOG.debug("Cleared verification cache ({} server, {} client entries)", serverCount, clientCount);
    }

    /**
     * Returns the estimated number of cached server verification results.
     *
     * @return estimated cache size
     */
    public long serverCacheSize() {
        return serverCache.estimatedSize();
    }

    /**
     * Returns the estimated number of cached client verification results.
     *
     * @return estimated cache size
     */
    public long clientCacheSize() {
        return clientCache.estimatedSize();
    }

    // ==================== Private Helpers ====================

    private String computeFingerprint(X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encoded);
            return HexFormat.of().formatHex(hash);
        } catch (CertificateEncodingException e) {
            LOG.warn("Failed to encode certificate for fingerprint: {}", e.getMessage());
            return null;
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available in all Java implementations
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    private String truncateFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.length() < 16) {
            return fingerprint;
        }
        return fingerprint.substring(0, 16) + "...";
    }

    // ==================== Caffeine Expiry for Variable TTL ====================

    /**
     * Custom Caffeine Expiry that applies different TTLs for positive and negative results.
     */
    private static class VariableTtlExpiry<V> implements Expiry<String, V> {
        private final long positiveTtlNanos;
        private final long negativeTtlNanos;
        private final Predicate<V> isSuccess;

        VariableTtlExpiry(Duration positiveTtl, Duration negativeTtl, Predicate<V> isSuccess) {
            this.positiveTtlNanos = positiveTtl.toNanos();
            this.negativeTtlNanos = negativeTtl.toNanos();
            this.isSuccess = isSuccess;
        }

        @Override
        public long expireAfterCreate(String key, V value, long currentTime) {
            return isSuccess.test(value) ? positiveTtlNanos : negativeTtlNanos;
        }

        @Override
        public long expireAfterUpdate(String key, V value, long currentTime, long currentDuration) {
            return expireAfterCreate(key, value, currentTime);
        }

        @Override
        public long expireAfterRead(String key, V value, long currentTime, long currentDuration) {
            return currentDuration; // No change on read
        }
    }

    // ==================== Builder ====================

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a caching service with default configuration.
     *
     * @return a new caching service wrapping the default verification service
     */
    public static CachingBadgeVerificationService create() {
        return builder()
            .delegate(BadgeVerificationService.create())
            .build();
    }

    /**
     * Builder for CachingBadgeVerificationService.
     */
    public static final class Builder {
        private BadgeVerificationService delegate;
        private Duration cacheTtl;
        private Duration negativeCacheTtl;

        private Builder() {
        }

        /**
         * Sets the underlying verification service to wrap.
         *
         * @param delegate the delegate service
         * @return this builder
         */
        public Builder delegate(BadgeVerificationService delegate) {
            this.delegate = delegate;
            return this;
        }

        /**
         * Sets the cache TTL for successful verification results.
         *
         * <p>Default: 15 minutes</p>
         *
         * @param ttl the cache TTL
         * @return this builder
         */
        public Builder cacheTtl(Duration ttl) {
            this.cacheTtl = ttl;
            return this;
        }

        /**
         * Sets the cache TTL for failed/negative verification results.
         *
         * <p>This is typically shorter than the positive cache TTL to allow
         * quicker recovery when an agent becomes registered.</p>
         *
         * <p>Default: 5 minutes</p>
         *
         * @param ttl the negative cache TTL
         * @return this builder
         */
        public Builder negativeCacheTtl(Duration ttl) {
            this.negativeCacheTtl = ttl;
            return this;
        }

        /**
         * Builds the caching service.
         *
         * @return the configured caching service
         */
        public CachingBadgeVerificationService build() {
            if (delegate == null) {
                throw new IllegalStateException("delegate is required");
            }
            return new CachingBadgeVerificationService(this);
        }
    }
}