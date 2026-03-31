package com.godaddy.ans.sdk.transparency;

import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.godaddy.ans.sdk.exception.AnsServerException;
import com.godaddy.ans.sdk.transparency.scitt.RefreshDecision;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Manages the lifecycle of the SCITT root key cache.
 *
 * <p>Handles fetching, caching, and cache-refresh logic for root public keys used
 * to verify SCITT receipts and status tokens. The underlying {@link HttpClient} is
 * a shared reference; this class does not own or close it.</p>
 */
class RootKeyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(RootKeyManager.class);

    private static final String ROOT_KEY_CACHE_KEY = "root";

    /**
     * Global cooldown between cache refresh attempts to prevent cache thrashing.
     */
    private static final Duration REFRESH_COOLDOWN = Duration.ofSeconds(30);

    /**
     * Maximum tolerance for artifact timestamps in the future (clock skew).
     */
    private static final Duration FUTURE_TOLERANCE = Duration.ofSeconds(60);

    /**
     * Tolerance for artifacts issued slightly before cache refresh (race conditions).
     */
    private static final Duration PAST_TOLERANCE = Duration.ofMinutes(5);

    private final HttpClient httpClient;
    private final String baseUrl;
    private final Duration readTimeout;

    // Root keys cache with automatic TTL and stampede prevention (keyed by hex key ID)
    private final AsyncLoadingCache<String, Map<String, PublicKey>> rootKeyCache;

    // Timestamp when cache was last populated (for refresh-on-miss logic)
    private final AtomicReference<Instant> cachePopulatedAt = new AtomicReference<>(Instant.EPOCH);

    // Timestamp of last refresh attempt (for cooldown enforcement)
    private final AtomicReference<Instant> lastRefreshAttempt = new AtomicReference<>(Instant.EPOCH);

    RootKeyManager(HttpClient httpClient, String baseUrl, Duration readTimeout, Duration rootKeyCacheTtl) {
        this.httpClient = httpClient;
        this.baseUrl = baseUrl;
        this.readTimeout = readTimeout;
        this.rootKeyCache = Caffeine.newBuilder()
            .maximumSize(1)
            .expireAfterWrite(rootKeyCacheTtl)
            .buildAsync((key, executor) -> fetchRootKeysFromServerAsync());
    }

    /**
     * Returns the SCITT root public keys asynchronously, using cached values if available.
     *
     * <p>The root keys are cached with a configurable TTL to avoid redundant
     * network calls on every verification request. Concurrent callers share
     * a single in-flight fetch to prevent cache stampedes.</p>
     *
     * <p>The returned map is keyed by hex key ID (4-byte SHA-256 of SPKI-DER),
     * enabling O(1) lookup by key ID from COSE headers.</p>
     *
     * @return a CompletableFuture with the root public keys for verifying receipts and status tokens
     */
    CompletableFuture<Map<String, PublicKey>> getRootKeysAsync() {
        return rootKeyCache.get(ROOT_KEY_CACHE_KEY);
    }

    /**
     * Invalidates the cached root key, forcing the next call to fetch from the server.
     */
    void invalidateRootKeyCache() {
        rootKeyCache.synchronous().invalidate(ROOT_KEY_CACHE_KEY);
        LOGGER.debug("Root key cache invalidated");
    }

    /**
     * Returns the timestamp when the root key cache was last populated.
     *
     * @return the cache population timestamp, or {@link Instant#EPOCH} if never populated
     */
    Instant getCachePopulatedAt() {
        return cachePopulatedAt.get();
    }

    /**
     * Attempts to refresh the root key cache if the artifact's issued-at timestamp
     * indicates it may have been signed with a new key not yet in our cache.
     *
     * <p>Security checks performed:</p>
     * <ol>
     *   <li>Reject artifacts claiming to be from the future (beyond clock skew tolerance)</li>
     *   <li>Reject artifacts older than our cache (key should already be present)</li>
     *   <li>Enforce global cooldown to prevent cache thrashing attacks</li>
     * </ol>
     *
     * @param artifactIssuedAt the issued-at timestamp from the SCITT artifact
     * @return a future containing the refresh decision with action, reason, and optionally refreshed keys
     */
    CompletableFuture<RefreshDecision> refreshRootKeysIfNeeded(Instant artifactIssuedAt) {
        Instant now = Instant.now();
        Instant cacheTime = cachePopulatedAt.get();

        // Check 1: Reject artifacts from the future (beyond clock skew tolerance)
        if (artifactIssuedAt.isAfter(now.plus(FUTURE_TOLERANCE))) {
            LOGGER.warn("Artifact timestamp {} is in the future (now={}), rejecting",
                artifactIssuedAt, now);
            return CompletableFuture.completedFuture(
                RefreshDecision.reject("Artifact timestamp is in the future"));
        }

        // Check 2: Reject artifacts older than cache (with past tolerance for race conditions)
        // If artifact was issued before we refreshed cache, the key SHOULD be there
        if (artifactIssuedAt.isBefore(cacheTime.minus(PAST_TOLERANCE))) {
            LOGGER.debug("Artifact issued at {} predates cache refresh at {} (with {}min tolerance), "
                + "key should be present - rejecting refresh",
                artifactIssuedAt, cacheTime, PAST_TOLERANCE.toMinutes());
            return CompletableFuture.completedFuture(
                RefreshDecision.reject("Key not found and artifact predates cache refresh"));
        }

        // Check 3: Enforce global cooldown to prevent cache thrashing
        Instant lastAttempt = lastRefreshAttempt.get();
        if (lastAttempt.plus(REFRESH_COOLDOWN).isAfter(now)) {
            Duration remaining = Duration.between(now, lastAttempt.plus(REFRESH_COOLDOWN));
            LOGGER.debug("Cache refresh on cooldown, {} remaining", remaining);
            return CompletableFuture.completedFuture(
                RefreshDecision.defer("Cache was recently refreshed, retry in " + remaining.toSeconds() + "s"));
        }

        // All checks passed - attempt refresh
        LOGGER.info("Artifact issued at {} is newer than cache at {}, refreshing root keys",
            artifactIssuedAt, cacheTime);

        // Atomically claim the refresh slot to prevent concurrent refresh attempts
        if (!lastRefreshAttempt.compareAndSet(lastAttempt, now)) {
            LOGGER.debug("Concurrent refresh already in progress, deferring");
            return CompletableFuture.completedFuture(
                RefreshDecision.defer("Concurrent refresh in progress"));
        }

        // Invalidate and fetch fresh keys asynchronously
        invalidateRootKeyCache();
        return getRootKeysAsync()
            .thenApply(freshKeys -> {
                LOGGER.info("Cache refresh complete, now have {} keys", freshKeys.size());
                return RefreshDecision.refreshed(freshKeys);
            })
            .exceptionally(e -> {
                Throwable cause = e instanceof CompletionException ? e.getCause() : e;
                LOGGER.error("Failed to refresh root keys: {}", cause.getMessage());
                return RefreshDecision.defer("Failed to refresh: " + cause.getMessage());
            });
    }

    /** Maximum number of retry attempts for root key fetch. */
    private static final int MAX_RETRIES = 2;

    /** Initial retry delay in milliseconds (doubles on each retry). */
    private static final long INITIAL_RETRY_DELAY_MS = 500;

    /**
     * Fetches the SCITT root public keys from the /root-keys endpoint asynchronously
     * with retry and exponential backoff.
     */
    private CompletableFuture<Map<String, PublicKey>> fetchRootKeysFromServerAsync() {
        return fetchRootKeysWithRetry(0);
    }

    private CompletableFuture<Map<String, PublicKey>> fetchRootKeysWithRetry(int attempt) {
        return doFetchRootKeys()
            .exceptionallyCompose(e -> {
                if (attempt < MAX_RETRIES) {
                    long delayMs = INITIAL_RETRY_DELAY_MS * (1L << attempt);
                    LOGGER.warn("Root key fetch failed (attempt {}/{}), retrying in {}ms: {}",
                        attempt + 1, MAX_RETRIES + 1, delayMs, e.getMessage());
                    return CompletableFuture.supplyAsync(() -> null,
                            CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS))
                        .thenCompose(ignored -> fetchRootKeysWithRetry(attempt + 1));
                }
                LOGGER.error("Root key fetch failed after {} attempts: {}",
                    MAX_RETRIES + 1, e.getMessage());
                return CompletableFuture.failedFuture(e);
            });
    }

    private CompletableFuture<Map<String, PublicKey>> doFetchRootKeys() {
        LOGGER.info("Fetching root keys from server");
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/root-keys"))
            .header("Accept", "text/plain")
            .timeout(readTimeout)
            .GET()
            .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenApply(response -> {
                if (response.statusCode() != 200) {
                    throw new AnsServerException(
                        "Failed to fetch root keys: HTTP " + response.statusCode(),
                        response.statusCode(),
                        response.headers().firstValue("X-Request-Id").orElse(null));
                }
                Map<String, PublicKey> keys = C2spKeyParser.parsePublicKeysResponse(response.body());
                cachePopulatedAt.set(Instant.now());
                LOGGER.info("Fetched and cached {} root key(s) at {}", keys.size(), cachePopulatedAt.get());
                return keys;
            });
    }
}
