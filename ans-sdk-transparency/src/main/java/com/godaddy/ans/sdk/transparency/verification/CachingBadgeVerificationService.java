package com.godaddy.ans.sdk.transparency.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;

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

    private final BadgeVerificationService delegate;
    private final Duration cacheTtl;
    private final Duration negativeCacheTtl;

    private final ConcurrentHashMap<String, CachedServerResult> serverCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CachedClientResult> clientCache = new ConcurrentHashMap<>();

    private CachingBadgeVerificationService(Builder builder) {
        this.delegate = builder.delegate;
        this.cacheTtl = builder.cacheTtl != null ? builder.cacheTtl : DEFAULT_CACHE_TTL;
        this.negativeCacheTtl = builder.negativeCacheTtl != null ? builder.negativeCacheTtl
                : DEFAULT_NEGATIVE_CACHE_TTL;
    }

    /**
     * Verifies a server against the transparency log, with caching.
     *
     * @param hostname the server hostname to verify
     * @return the verification result (may be cached)
     */
    public ServerVerificationResult verifyServer(String hostname) {
        // Check cache first
        CachedServerResult cached = serverCache.get(hostname);
        if (cached != null && !cached.isExpired()) {
            LOG.debug("Cache hit for server verification: {}", hostname);
            return cached.result;
        }

        // Lazy eviction: remove expired entry immediately to free memory
        if (cached != null) {
            serverCache.remove(hostname);
            LOG.debug("Lazily evicted expired server cache entry: {}", hostname);
        }

        // Cache miss - perform verification
        LOG.debug("Cache miss for server verification: {}", hostname);
        ServerVerificationResult result = delegate.verifyServer(hostname);

        // Cache the result
        Duration ttl = result.isSuccess() ? cacheTtl : negativeCacheTtl;
        serverCache.put(hostname, new CachedServerResult(result, ttl));
        LOG.debug("Cached server verification result for {} (ttl={})", hostname, ttl);

        return result;
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
        // Compute fingerprint for cache key
        String fingerprint = computeFingerprint(clientCert);
        if (fingerprint == null) {
            // Can't cache without fingerprint - delegate directly
            return delegate.verifyClient(clientCert);
        }

        // Check cache first
        CachedClientResult cached = clientCache.get(fingerprint);
        if (cached != null && !cached.isExpired()) {
            LOG.debug("Cache hit for client verification: {}", truncateFingerprint(fingerprint));
            return cached.result;
        }

        // Lazy eviction: remove expired entry immediately to free memory
        if (cached != null) {
            clientCache.remove(fingerprint);
            LOG.debug("Lazily evicted expired client cache entry: {}", truncateFingerprint(fingerprint));
        }

        // Cache miss - perform verification
        LOG.debug("Cache miss for client verification: {}", truncateFingerprint(fingerprint));
        ClientVerificationResult result = delegate.verifyClient(clientCert);

        // Cache the result
        Duration ttl = result.isSuccess() ? cacheTtl : negativeCacheTtl;
        clientCache.put(fingerprint, new CachedClientResult(result, ttl));
        LOG.debug("Cached client verification result for {} (ttl={})", truncateFingerprint(fingerprint), ttl);

        return result;
    }

    // ==================== Cache Management ====================

    /**
     * Invalidates the cached result for a specific server.
     *
     * @param hostname the hostname to invalidate
     */
    public void invalidateServer(String hostname) {
        if (serverCache.remove(hostname) != null) {
            LOG.debug("Invalidated server cache for: {}", hostname);
        }
    }

    /**
     * Invalidates the cached result for a specific client certificate.
     *
     * @param clientCert the certificate to invalidate
     */
    public void invalidateClient(X509Certificate clientCert) {
        String fingerprint = computeFingerprint(clientCert);
        if (fingerprint != null && clientCache.remove(fingerprint) != null) {
            LOG.debug("Invalidated client cache for: {}", truncateFingerprint(fingerprint));
        }
    }

    /**
     * Clears all cached verification results.
     */
    public void clearCache() {
        int serverCount = serverCache.size();
        int clientCount = clientCache.size();
        serverCache.clear();
        clientCache.clear();
        LOG.debug("Cleared verification cache ({} server, {} client entries)", serverCount, clientCount);
    }

    /**
     * Returns the number of cached server verification results.
     */
    public int serverCacheSize() {
        return serverCache.size();
    }

    /**
     * Returns the number of cached client verification results.
     */
    public int clientCacheSize() {
        return clientCache.size();
    }

    /**
     * Removes expired entries from both caches.
     *
     * <p>Call this periodically to prevent memory buildup from expired entries.</p>
     */
    public void evictExpired() {
        int serverEvicted = 0;
        int clientEvicted = 0;

        var serverIt = serverCache.entrySet().iterator();
        while (serverIt.hasNext()) {
            if (serverIt.next().getValue().isExpired()) {
                serverIt.remove();
                serverEvicted++;
            }
        }

        var clientIt = clientCache.entrySet().iterator();
        while (clientIt.hasNext()) {
            if (clientIt.next().getValue().isExpired()) {
                clientIt.remove();
                clientEvicted++;
            }
        }

        if (serverEvicted > 0 || clientEvicted > 0) {
            LOG.debug("Evicted {} server and {} client expired cache entries", serverEvicted, clientEvicted);
        }
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

    // ==================== Cache Entry Classes ====================

    private static class CachedServerResult {
        final ServerVerificationResult result;
        final Instant expiresAt;

        CachedServerResult(ServerVerificationResult result, Duration ttl) {
            this.result = result;
            this.expiresAt = Instant.now().plus(ttl);
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    private static class CachedClientResult {
        final ClientVerificationResult result;
        final Instant expiresAt;

        CachedClientResult(ClientVerificationResult result, Duration ttl) {
            this.result = result;
            this.expiresAt = Instant.now().plus(ttl);
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
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