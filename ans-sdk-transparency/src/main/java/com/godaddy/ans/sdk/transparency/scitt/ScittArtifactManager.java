package com.godaddy.ans.sdk.transparency.scitt;

import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Manages SCITT artifact lifecycle including fetching, caching, and background refresh.
 *
 * <p><b>Intended use case:</b> This class is designed for <em>server-side</em> or
 * <em>proactive-fetch</em> scenarios where an agent needs to pre-fetch and cache its
 * own SCITT artifacts to include in outgoing HTTP response headers. It is <em>not</em>
 * used in the client verification flow, which extracts artifacts from incoming HTTP headers
 * via {@link ScittHeaderProvider}.</p>
 *
 * <p>This manager handles:</p>
 * <ul>
 *   <li>Fetching receipts and status tokens from the transparency log</li>
 *   <li>Caching artifacts to avoid redundant network calls</li>
 *   <li>Background refresh of status tokens before expiry</li>
 *   <li>Graceful shutdown of background tasks</li>
 * </ul>
 *
 * <h2>Server-Side Usage</h2>
 * <pre>{@code
 * // On agent startup
 * ScittArtifactManager manager = ScittArtifactManager.builder()
 *     .transparencyClient(client)
 *     .build();
 *
 * // Start background refresh to keep token fresh
 * manager.startBackgroundRefresh(myAgentId);
 *
 * // When handling requests, get pre-computed Base64 strings for response headers
 * String receiptBase64 = manager.getReceiptBase64(myAgentId).join();
 * String tokenBase64 = manager.getStatusTokenBase64(myAgentId).join();
 * response.addHeader("X-SCITT-Receipt", receiptBase64);
 * response.addHeader("X-ANS-Status-Token", tokenBase64);
 *
 * // On shutdown
 * manager.close();
 * }</pre>
 *
 * @see ScittHeaderProvider#getOutgoingHeaders()
 * @see TransparencyClient#getReceiptAsync(String)
 * @see TransparencyClient#getStatusTokenAsync(String)
 * @see ScittVerifierAdapter for client-side verification
 */
public class ScittArtifactManager implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScittArtifactManager.class);

    private static final int DEFAULT_CACHE_SIZE = 1000;

    private final TransparencyClient transparencyClient;
    private final ScheduledExecutorService scheduler;
    private final Executor ioExecutor;
    private final boolean ownsScheduler;

    // Caffeine caches with automatic stampede prevention
    private final AsyncLoadingCache<String, CachedReceipt> receiptCache;
    private final AsyncLoadingCache<String, CachedToken> tokenCache;

    // Background refresh tracking
    private final Map<String, ScheduledFuture<?>> refreshTasks;

    private volatile boolean closed = false;

    private ScittArtifactManager(Builder builder) {
        this.transparencyClient = Objects.requireNonNull(builder.transparencyClient,
            "transparencyClient cannot be null");

        if (builder.scheduler != null) {
            this.scheduler = builder.scheduler;
            this.ownsScheduler = false;
        } else {
            this.scheduler = AnsExecutors.newSingleThreadScheduledExecutor();
            this.ownsScheduler = true;
        }

        // Use shared I/O executor for blocking HTTP work - keeps scheduler thread free for timing
        this.ioExecutor = AnsExecutors.sharedIoExecutor();

        // Receipts are immutable Merkle proofs - cache indefinitely, evict only by LRU
        this.receiptCache = Caffeine.newBuilder()
            .maximumSize(DEFAULT_CACHE_SIZE)
            .executor(ioExecutor)
            .buildAsync(this::loadReceipt);

        // Build token cache with dynamic expiry based on token's expiresAt()
        this.tokenCache = Caffeine.newBuilder()
            .maximumSize(DEFAULT_CACHE_SIZE)
            .expireAfter(new StatusTokenExpiry())
            .executor(ioExecutor)
            .buildAsync(this::loadToken);

        this.refreshTasks = new ConcurrentHashMap<>();
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
     * Fetches the SCITT receipt for an agent.
     *
     * <p>Receipts are cached indefinitely since they are immutable Merkle inclusion proofs.
     * Concurrent callers share a single in-flight fetch to prevent stampedes.</p>
     *
     * @param agentId the agent's unique identifier
     * @return future containing the receipt
     */
    public CompletableFuture<ScittReceipt> getReceipt(String agentId) {
        Objects.requireNonNull(agentId, "agentId cannot be null");

        if (closed) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("ScittArtifactManager is closed"));
        }

        return receiptCache.get(agentId).thenApply(CachedReceipt::receipt);
    }

    /**
     * Fetches the Base64-encoded SCITT receipt for an agent.
     *
     * <p>This method returns the pre-computed Base64 string ready for use in
     * HTTP headers. The Base64 encoding is computed once at cache-fill time,
     * avoiding byte array allocation on each call.</p>
     *
     * @param agentId the agent's unique identifier
     * @return future containing the Base64-encoded receipt
     */
    public CompletableFuture<String> getReceiptBase64(String agentId) {
        Objects.requireNonNull(agentId, "agentId cannot be null");

        if (closed) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("ScittArtifactManager is closed"));
        }

        return receiptCache.get(agentId).thenApply(CachedReceipt::base64);
    }

    /**
     * Fetches the status token for an agent.
     *
     * <p>Tokens are cached but have shorter TTL based on their expiry time.</p>
     *
     * @param agentId the agent's unique identifier
     * @return future containing the status token
     */
    public CompletableFuture<StatusToken> getStatusToken(String agentId) {
        Objects.requireNonNull(agentId, "agentId cannot be null");

        if (closed) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("ScittArtifactManager is closed"));
        }

        return tokenCache.get(agentId).thenApply(CachedToken::token);
    }

    /**
     * Fetches the Base64-encoded status token for an agent.
     *
     * <p>This method returns the pre-computed Base64 string ready for use in
     * HTTP headers. The Base64 encoding is computed once at cache-fill time,
     * avoiding byte array allocation on each call.</p>
     *
     * @param agentId the agent's unique identifier
     * @return future containing the Base64-encoded status token
     */
    public CompletableFuture<String> getStatusTokenBase64(String agentId) {
        Objects.requireNonNull(agentId, "agentId cannot be null");

        if (closed) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("ScittArtifactManager is closed"));
        }

        return tokenCache.get(agentId).thenApply(CachedToken::base64);
    }

    /**
     * Starts background refresh for an agent's status token.
     *
     * <p>The refresh interval is computed as (exp - iat) / 2 from the token,
     * ensuring the token is refreshed before expiry.</p>
     *
     * @param agentId the agent's unique identifier
     */
    public void startBackgroundRefresh(String agentId) {
        Objects.requireNonNull(agentId, "agentId cannot be null");

        if (closed) {
            LOGGER.warn("Cannot start background refresh - manager is closed");
            return;
        }

        // Get current token to compute refresh interval
        CachedToken cached = tokenCache.synchronous().getIfPresent(agentId);
        Duration refreshInterval = cached != null
            ? cached.token().computeRefreshInterval()
            : Duration.ofMinutes(5);

        scheduleRefresh(agentId, refreshInterval);
    }

    /**
     * Stops background refresh for an agent.
     *
     * @param agentId the agent's unique identifier
     */
    public void stopBackgroundRefresh(String agentId) {
        ScheduledFuture<?> task = refreshTasks.remove(agentId);
        if (task != null) {
            task.cancel(false);
            LOGGER.debug("Stopped background refresh for agent {}", agentId);
        }
    }

    /**
     * Clears all cached artifacts for an agent.
     *
     * @param agentId the agent's unique identifier
     */
    public void clearCache(String agentId) {
        receiptCache.synchronous().invalidate(agentId);
        tokenCache.synchronous().invalidate(agentId);
        LOGGER.debug("Cleared cache for agent {}", agentId);
    }

    /**
     * Clears all cached artifacts.
     */
    public void clearAllCaches() {
        receiptCache.synchronous().invalidateAll();
        tokenCache.synchronous().invalidateAll();
        LOGGER.info("Cleared all SCITT artifact caches");
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }

        closed = true;
        LOGGER.info("Shutting down ScittArtifactManager");

        // Cancel all refresh tasks
        refreshTasks.values().forEach(task -> task.cancel(false));
        refreshTasks.clear();

        // Shutdown scheduler if we own it
        if (ownsScheduler) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        clearAllCaches();
    }

    // ==================== Cache Loaders ====================

    private CachedReceipt loadReceipt(String agentId) {
        LOGGER.info("Fetching receipt for agent from TL {}", agentId);
        try {
            byte[] receiptBytes = transparencyClient.getReceipt(agentId);
            ScittReceipt receipt = ScittReceipt.parse(receiptBytes);
            LOGGER.info("Fetched and cached receipt for agent {} from TL", agentId);
            return new CachedReceipt(receipt, receiptBytes);
        } catch (Exception e) {
            LOGGER.error("Failed to fetch receipt for agent {}: {}", agentId, e.getMessage());
            throw new ScittFetchException(
                "Failed to fetch receipt: " + e.getMessage(), e,
                ScittFetchException.ArtifactType.RECEIPT, agentId);
        }
    }

    private CachedToken loadToken(String agentId) {
        LOGGER.info("Fetching status token for agent {}", agentId);
        try {
            byte[] tokenBytes = transparencyClient.getStatusToken(agentId);
            StatusToken token = StatusToken.parse(tokenBytes);
            LOGGER.info("Fetched and cached status token for agent {} (expires {})",
                agentId, token.expiresAt());
            return new CachedToken(token, tokenBytes);
        } catch (Exception e) {
            LOGGER.error("Failed to fetch status token for agent {}: {}", agentId, e.getMessage());
            throw new ScittFetchException(
                "Failed to fetch status token: " + e.getMessage(), e,
                ScittFetchException.ArtifactType.STATUS_TOKEN, agentId);
        }
    }

    // ==================== Background Refresh ====================

    private void scheduleRefresh(String agentId, Duration interval) {
        // Cancel existing task if any
        stopBackgroundRefresh(agentId);

        if (closed) {
            return;
        }

        LOGGER.debug("Scheduling status token refresh for agent {} in {}", agentId, interval);

        // Use schedule() instead of scheduleAtFixedRate() so we can adjust interval after each refresh
        ScheduledFuture<?> task = scheduler.schedule(
            () -> refreshToken(agentId),
            interval.toMillis(),
            TimeUnit.MILLISECONDS
        );

        refreshTasks.put(agentId, task);
    }

    private void refreshToken(String agentId) {
        if (closed) {
            return;
        }

        LOGGER.debug("Background refresh triggered for agent {}", agentId);

        // Use Caffeine's refresh which handles stampede prevention
        tokenCache.synchronous().refresh(agentId);

        // Reschedule with new interval based on refreshed token
        CachedToken refreshed = tokenCache.synchronous().getIfPresent(agentId);
        if (refreshed != null && !closed) {
            Duration newInterval = refreshed.token().computeRefreshInterval();
            scheduleRefresh(agentId, newInterval);
        }
    }

    // ==================== Caffeine Expiry for Status Tokens ====================

    /**
     * Custom expiry that uses the token's own expiration time.
     */
    private static class StatusTokenExpiry implements Expiry<String, CachedToken> {
        @Override
        public long expireAfterCreate(String key, CachedToken value, long currentTime) {
            if (value.token().isExpired()) {
                return 0; // Already expired
            }
            Duration remaining = Duration.between(Instant.now(), value.token().expiresAt());
            return Math.max(0, remaining.toNanos());
        }

        @Override
        public long expireAfterUpdate(String key, CachedToken value,
                                       long currentTime, long currentDuration) {
            return expireAfterCreate(key, value, currentTime);
        }

        @Override
        public long expireAfterRead(String key, CachedToken value,
                                     long currentTime, long currentDuration) {
            return currentDuration; // No change on read
        }
    }

    // ==================== Cache Entry Records ====================

    /**
     * Cached receipt with pre-computed Base64 for header encoding.
     */
    private record CachedReceipt(ScittReceipt receipt, String base64) {
        CachedReceipt(ScittReceipt receipt, byte[] rawBytes) {
            this(receipt, Base64.getEncoder().encodeToString(rawBytes));
        }
    }

    /**
     * Cached status token with pre-computed Base64 for header encoding.
     */
    private record CachedToken(StatusToken token, String base64) {
        CachedToken(StatusToken token, byte[] rawBytes) {
            this(token, Base64.getEncoder().encodeToString(rawBytes));
        }
    }

    // ==================== Builder ====================

    /**
     * Builder for ScittArtifactManager.
     */
    public static class Builder {
        private TransparencyClient transparencyClient;
        private ScheduledExecutorService scheduler;

        /**
         * Sets the transparency client for fetching artifacts.
         *
         * @param client the transparency client
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient client) {
            this.transparencyClient = client;
            return this;
        }

        /**
         * Sets a custom scheduler for background refresh.
         *
         * <p>If not set, a single-threaded scheduler will be created
         * and managed by this manager.</p>
         *
         * @param scheduler the scheduler
         * @return this builder
         */
        public Builder scheduler(ScheduledExecutorService scheduler) {
            this.scheduler = scheduler;
            return this;
        }

        /**
         * Builds the ScittArtifactManager.
         *
         * @return the configured manager
         */
        public ScittArtifactManager build() {
            return new ScittArtifactManager(this);
        }
    }
}
