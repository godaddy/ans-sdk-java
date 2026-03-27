package com.godaddy.ans.sdk.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CryptoCache}.
 */
class CryptoCacheTest {

    @Test
    @DisplayName("sha256 should compute correct hash")
    void sha256ShouldComputeCorrectHash() throws Exception {
        byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);

        byte[] result = CryptoCache.sha256(data);

        // Verify against direct MessageDigest
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] expected = md.digest(data);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    @DisplayName("sha256 should return 32 bytes")
    void sha256ShouldReturn32Bytes() {
        byte[] data = "test data".getBytes(StandardCharsets.UTF_8);

        byte[] result = CryptoCache.sha256(data);

        assertThat(result).hasSize(32);
    }

    @Test
    @DisplayName("sha256 should handle empty input")
    void sha256ShouldHandleEmptyInput() throws Exception {
        byte[] data = new byte[0];

        byte[] result = CryptoCache.sha256(data);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] expected = md.digest(data);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    @DisplayName("sha256 should produce consistent results")
    void sha256ShouldProduceConsistentResults() {
        byte[] data = "consistent test".getBytes(StandardCharsets.UTF_8);

        byte[] result1 = CryptoCache.sha256(data);
        byte[] result2 = CryptoCache.sha256(data);

        assertThat(result1).isEqualTo(result2);
    }

    @Test
    @DisplayName("sha256 should be thread-safe")
    void sha256ShouldBeThreadSafe() throws Exception {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicReference<byte[]> firstResult = new AtomicReference<>();
        AtomicReference<AssertionError> error = new AtomicReference<>();

        byte[] data = "concurrent test".getBytes(StandardCharsets.UTF_8);

        try {
            for (int i = 0; i < threadCount; i++) {
                executor.execute(() -> {
                    try {
                        startLatch.await();
                        byte[] result = CryptoCache.sha256(data);
                        firstResult.compareAndSet(null, result);
                        if (!java.util.Arrays.equals(result, firstResult.get())) {
                            error.set(new AssertionError("Hash mismatch in concurrent execution"));
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertThat(doneLatch.await(10, TimeUnit.SECONDS)).isTrue();
            assertThat(error.get()).isNull();
            assertThat(firstResult.get()).isNotNull();
        } finally {
            executor.shutdown();
        }
    }

    @Test
    @DisplayName("sha512 should compute correct hash")
    void sha512ShouldComputeCorrectHash() throws Exception {
        byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);

        byte[] result = CryptoCache.sha512(data);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] expected = md.digest(data);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    @DisplayName("sha512 should return 64 bytes")
    void sha512ShouldReturn64Bytes() {
        byte[] data = "test data".getBytes(StandardCharsets.UTF_8);

        byte[] result = CryptoCache.sha512(data);

        assertThat(result).hasSize(64);
    }

    @Test
    @DisplayName("sha512 should handle empty input")
    void sha512ShouldHandleEmptyInput() throws Exception {
        byte[] data = new byte[0];

        byte[] result = CryptoCache.sha512(data);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] expected = md.digest(data);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    @DisplayName("sha512 should produce consistent results")
    void sha512ShouldProduceConsistentResults() {
        byte[] data = "consistent test".getBytes(StandardCharsets.UTF_8);

        byte[] result1 = CryptoCache.sha512(data);
        byte[] result2 = CryptoCache.sha512(data);

        assertThat(result1).isEqualTo(result2);
    }

    @Test
    @DisplayName("sha512 should be thread-safe")
    void sha512ShouldBeThreadSafe() throws Exception {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicReference<byte[]> firstResult = new AtomicReference<>();
        AtomicReference<AssertionError> error = new AtomicReference<>();

        byte[] data = "concurrent test".getBytes(StandardCharsets.UTF_8);

        try {
            for (int i = 0; i < threadCount; i++) {
                executor.execute(() -> {
                    try {
                        startLatch.await();
                        byte[] result = CryptoCache.sha512(data);
                        firstResult.compareAndSet(null, result);
                        if (!java.util.Arrays.equals(result, firstResult.get())) {
                            error.set(new AssertionError("Hash mismatch in concurrent execution"));
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertThat(doneLatch.await(10, TimeUnit.SECONDS)).isTrue();
            assertThat(error.get()).isNull();
            assertThat(firstResult.get()).isNotNull();
        } finally {
            executor.shutdown();
        }
    }

    @Test
    @DisplayName("sha256 and sha512 should produce different hashes")
    void sha256AndSha512ShouldProduceDifferentHashes() {
        byte[] data = "same input".getBytes(StandardCharsets.UTF_8);

        byte[] sha256Result = CryptoCache.sha256(data);
        byte[] sha512Result = CryptoCache.sha512(data);

        assertThat(sha256Result).isNotEqualTo(sha512Result);
        assertThat(sha256Result).hasSize(32);
        assertThat(sha512Result).hasSize(64);
    }

    @Test
    @DisplayName("verifyEs256 should verify valid signature")
    void verifyEs256ShouldVerifyValidSignature() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] data = "test data to sign".getBytes(StandardCharsets.UTF_8);

        // Sign with standard Signature API
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // Verify with CryptoCache
        boolean result = CryptoCache.verifyEs256(data, signature, keyPair.getPublic());

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("verifyEs256 should reject invalid signature")
    void verifyEs256ShouldRejectInvalidSignature() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] data = "test data to sign".getBytes(StandardCharsets.UTF_8);

        // Sign with standard Signature API
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // Verify with different data
        byte[] differentData = "different data".getBytes(StandardCharsets.UTF_8);
        boolean result = CryptoCache.verifyEs256(differentData, signature, keyPair.getPublic());

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("verifyEs256 should be thread-safe")
    void verifyEs256ShouldBeThreadSafe() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] data = "concurrent test data".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        AtomicBoolean allValid = new AtomicBoolean(true);
        AtomicReference<Exception> error = new AtomicReference<>();

        try {
            for (int i = 0; i < threadCount; i++) {
                executor.execute(() -> {
                    try {
                        startLatch.await();
                        boolean result = CryptoCache.verifyEs256(data, signature, keyPair.getPublic());
                        if (!result) {
                            allValid.set(false);
                        }
                    } catch (Exception e) {
                        error.set(e);
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertThat(doneLatch.await(10, TimeUnit.SECONDS)).isTrue();
            assertThat(error.get()).isNull();
            assertThat(allValid.get()).isTrue();
        } finally {
            executor.shutdown();
        }
    }
}
