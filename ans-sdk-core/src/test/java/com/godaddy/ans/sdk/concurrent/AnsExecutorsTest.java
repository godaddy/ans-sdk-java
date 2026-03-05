package com.godaddy.ans.sdk.concurrent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AnsExecutors}.
 */
class AnsExecutorsTest {

    @AfterEach
    void tearDown() {
        // Clean up shared executor between tests
        AnsExecutors.shutdown();
    }

    @Test
    @DisplayName("sharedIoExecutor should return same instance on multiple calls")
    void sharedIoExecutorShouldReturnSameInstance() {
        Executor first = AnsExecutors.sharedIoExecutor();
        Executor second = AnsExecutors.sharedIoExecutor();

        assertThat(first).isSameAs(second);
    }

    @Test
    @DisplayName("sharedIoExecutor should execute tasks")
    void sharedIoExecutorShouldExecuteTasks() throws Exception {
        Executor executor = AnsExecutors.sharedIoExecutor();
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> threadName = new AtomicReference<>();

        executor.execute(() -> {
            threadName.set(Thread.currentThread().getName());
            latch.countDown();
        });

        assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(threadName.get()).startsWith("ans-io-");
    }

    @Test
    @DisplayName("sharedIoExecutor threads should be daemon threads")
    void sharedIoExecutorThreadsShouldBeDaemon() throws Exception {
        Executor executor = AnsExecutors.sharedIoExecutor();
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Boolean> isDaemon = new AtomicReference<>();

        executor.execute(() -> {
            isDaemon.set(Thread.currentThread().isDaemon());
            latch.countDown();
        });

        assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(isDaemon.get()).isTrue();
    }

    @Test
    @DisplayName("isInitialized should return false before first use")
    void isInitializedShouldReturnFalseBeforeFirstUse() {
        // After tearDown, executor should be null
        assertThat(AnsExecutors.isInitialized()).isFalse();
    }

    @Test
    @DisplayName("isInitialized should return true after first use")
    void isInitializedShouldReturnTrueAfterFirstUse() {
        AnsExecutors.sharedIoExecutor();
        assertThat(AnsExecutors.isInitialized()).isTrue();
    }

    @Test
    @DisplayName("shutdown should allow re-initialization")
    void shutdownShouldAllowReInitialization() {
        Executor first = AnsExecutors.sharedIoExecutor();
        AnsExecutors.shutdown();
        assertThat(AnsExecutors.isInitialized()).isFalse();

        Executor second = AnsExecutors.sharedIoExecutor();
        assertThat(AnsExecutors.isInitialized()).isTrue();
        assertThat(second).isNotSameAs(first);
    }

    @Test
    @DisplayName("newIoExecutor should create independent executor")
    void newIoExecutorShouldCreateIndependentExecutor() throws Exception {
        ExecutorService custom = AnsExecutors.newIoExecutor(2);
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> threadName = new AtomicReference<>();

        try {
            custom.execute(() -> {
                threadName.set(Thread.currentThread().getName());
                latch.countDown();
            });

            assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(threadName.get()).startsWith("ans-io-");
        } finally {
            custom.shutdown();
        }

        // Custom executor is not the shared one
        assertThat(custom).isNotSameAs(AnsExecutors.sharedIoExecutor());
    }

    @Test
    @DisplayName("DEFAULT_POOL_SIZE should be reasonable")
    void defaultPoolSizeShouldBeReasonable() {
        assertThat(AnsExecutors.DEFAULT_POOL_SIZE).isGreaterThanOrEqualTo(5);
        assertThat(AnsExecutors.DEFAULT_POOL_SIZE).isLessThanOrEqualTo(50);
    }

    @Test
    @DisplayName("sharedIoExecutor threads should have NORM_PRIORITY")
    void sharedIoExecutorThreadsShouldHaveNormalPriority() throws Exception {
        Executor executor = AnsExecutors.sharedIoExecutor();
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Integer> priority = new AtomicReference<>();

        executor.execute(() -> {
            priority.set(Thread.currentThread().getPriority());
            latch.countDown();
        });

        assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(priority.get()).isEqualTo(Thread.NORM_PRIORITY);
    }

    @Test
    @DisplayName("shutdown should be idempotent")
    void shutdownShouldBeIdempotent() {
        AnsExecutors.sharedIoExecutor();
        assertThat(AnsExecutors.isInitialized()).isTrue();

        // Multiple shutdowns should not throw
        AnsExecutors.shutdown();
        AnsExecutors.shutdown();
        AnsExecutors.shutdown();

        assertThat(AnsExecutors.isInitialized()).isFalse();
    }

    @Test
    @DisplayName("shutdown when not initialized should not throw")
    void shutdownWhenNotInitializedShouldNotThrow() {
        assertThat(AnsExecutors.isInitialized()).isFalse();
        AnsExecutors.shutdown();  // Should not throw
        assertThat(AnsExecutors.isInitialized()).isFalse();
    }

    @Test
    @DisplayName("concurrent access to sharedIoExecutor should be safe")
    void concurrentAccessToSharedIoExecutorShouldBeSafe() throws Exception {
        int threadCount = 10;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicReference<Executor> firstExecutor = new AtomicReference<>();

        for (int i = 0; i < threadCount; i++) {
            new Thread(() -> {
                try {
                    startLatch.await();
                    Executor executor = AnsExecutors.sharedIoExecutor();
                    firstExecutor.compareAndSet(null, executor);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            }).start();
        }

        startLatch.countDown();
        assertThat(doneLatch.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(firstExecutor.get()).isNotNull();
    }
}
