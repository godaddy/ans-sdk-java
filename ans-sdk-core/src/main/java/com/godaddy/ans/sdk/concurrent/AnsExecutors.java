package com.godaddy.ans.sdk.concurrent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Provides shared executors for ANS SDK operations.
 *
 * <p>This class provides a single shared thread pool for all verification and async operations
 * across all SDK modules, avoiding the resource waste of multiple thread pools. The shared pool
 * uses daemon threads so it won't prevent JVM shutdown.</p>
 *
 * <h2>Default Configuration</h2>
 * <ul>
 *   <li>Pool size: 10 threads (suitable for most use cases)</li>
 *   <li>Queue capacity: 100 tasks (bounded for back-pressure)</li>
 *   <li>Thread naming: "ans-io-{n}" for easy identification in thread dumps</li>
 *   <li>Daemon threads: Yes (won't prevent JVM shutdown)</li>
 *   <li>Rejection policy: CallerRunsPolicy (executes on caller thread when queue is full)</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Use the shared executor (recommended)
 * DaneVerifier verifier = new DaneVerifier(tlsaVerifier, AnsExecutors.sharedIoExecutor());
 *
 * // Or provide your own
 * Executor myExecutor = Executors.newFixedThreadPool(5);
 * DaneVerifier verifier = new DaneVerifier(tlsaVerifier, myExecutor);
 *
 * // Shutdown on application exit (optional - daemon threads will stop anyway)
 * AnsExecutors.shutdown();
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>All methods are thread-safe. The shared executor is lazily initialized on first access.</p>
 */
public final class AnsExecutors {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnsExecutors.class);

    /**
     * Default number of threads in the shared pool.
     * This is suitable for typical verification workloads involving DNS and HTTP I/O.
     */
    public static final int DEFAULT_POOL_SIZE = 10;

    /**
     * Default queue capacity for bounded task queues.
     * When the queue is full, tasks are executed on the caller's thread (back-pressure).
     */
    public static final int DEFAULT_QUEUE_CAPACITY = 100;

    private static volatile ExecutorService sharedExecutor;
    private static final Object LOCK = new Object();

    private AnsExecutors() {
        // Utility class
    }

    /**
     * Returns the shared I/O executor for ANS SDK operations.
     *
     * <p>This executor is suitable for blocking I/O operations like DNS lookups,
     * HTTP requests, and transparency log queries. It uses a fixed thread pool
     * with daemon threads.</p>
     *
     * <p>The executor is lazily initialized on first call and shared across all
     * SDK components that use the default executor.</p>
     *
     * @return the shared executor
     */
    public static Executor sharedIoExecutor() {
        ExecutorService executor = sharedExecutor;
        if (executor == null) {
            synchronized (LOCK) {
                executor = sharedExecutor;
                if (executor == null) {
                    executor = createSharedExecutor(DEFAULT_POOL_SIZE);
                    sharedExecutor = executor;
                    LOGGER.debug("Created shared ANS I/O executor with {} threads", DEFAULT_POOL_SIZE);
                }
            }
        }
        return executor;
    }

    /**
     * Creates a new I/O executor with the specified pool size.
     *
     * <p>Use this method if you need a dedicated executor with different sizing.
     * The returned executor is NOT shared and should be managed by the caller.
     * Uses a bounded queue with CallerRunsPolicy for back-pressure.</p>
     *
     * @param poolSize the number of threads in the pool
     * @return a new executor
     */
    public static ExecutorService newIoExecutor(int poolSize) {
        return new ThreadPoolExecutor(
            poolSize, poolSize,
            60L, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(DEFAULT_QUEUE_CAPACITY),
            new AnsThreadFactory(),
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }

    /**
     * Creates a new scheduled executor with the specified core pool size.
     *
     * <p>Use this for operations that need to run on a schedule, such as
     * SCITT artifact refresh or cache expiration.</p>
     *
     * @param corePoolSize the number of threads to keep in the pool
     * @return a new scheduled executor
     */
    public static ScheduledExecutorService newScheduledExecutor(int corePoolSize) {
        return Executors.newScheduledThreadPool(corePoolSize, new AnsThreadFactory("ans-scheduled"));
    }

    /**
     * Creates a new single-threaded scheduled executor.
     *
     * <p>Use this for lightweight scheduled tasks that don't need parallelism.</p>
     *
     * @return a new single-threaded scheduled executor
     */
    public static ScheduledExecutorService newSingleThreadScheduledExecutor() {
        return newScheduledExecutor(1);
    }

    /**
     * Shuts down the shared executor gracefully.
     *
     * <p>This is optional since the executor uses daemon threads which will be
     * terminated automatically when the JVM exits. However, calling this method
     * allows for graceful shutdown of in-flight operations.</p>
     *
     * <p>After shutdown, subsequent calls to {@link #sharedIoExecutor()} will
     * create a new executor.</p>
     */
    public static void shutdown() {
        synchronized (LOCK) {
            if (sharedExecutor != null) {
                LOGGER.debug("Shutting down shared ANS I/O executor");
                sharedExecutor.shutdown();
                try {
                    if (!sharedExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                        sharedExecutor.shutdownNow();
                        LOGGER.warn("Shared executor did not terminate gracefully, forced shutdown");
                    }
                } catch (InterruptedException e) {
                    sharedExecutor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
                sharedExecutor = null;
            }
        }
    }

    /**
     * Returns whether the shared executor has been initialized.
     *
     * <p>This method reads the volatile field directly without synchronization,
     * which is safe for this diagnostic/testing use case.</p>
     *
     * @return true if the shared executor exists
     */
    public static boolean isInitialized() {
        return sharedExecutor != null;
    }

    private static ExecutorService createSharedExecutor(int poolSize) {
        return newIoExecutor(poolSize);
    }

    /**
     * Thread factory that creates daemon threads with descriptive names.
     */
    private static class AnsThreadFactory implements ThreadFactory {
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;

        AnsThreadFactory() {
            this("ans-io");
        }

        AnsThreadFactory(String namePrefix) {
            this.namePrefix = namePrefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, namePrefix + "-" + threadNumber.getAndIncrement());
            t.setDaemon(true);
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }
}
