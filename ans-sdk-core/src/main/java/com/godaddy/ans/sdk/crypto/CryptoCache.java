package com.godaddy.ans.sdk.crypto;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Thread-local cache for cryptographic primitives.
 *
 * <p>This class provides cached access to commonly-used cryptographic objects
 * like {@link MessageDigest} and {@link Signature}, avoiding the overhead of
 * creating new instances for each operation. These instances are not thread-safe,
 * so this class uses {@link ThreadLocal} to provide each thread with its own instance.</p>
 *
 * <h2>Performance</h2>
 * <p>Creating MessageDigest and Signature instances involves synchronization and provider
 * lookup. Caching instances per-thread eliminates this overhead for repeated
 * operations on the same thread.</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Instead of:
 * MessageDigest md = MessageDigest.getInstance("SHA-256");
 * byte[] hash = md.digest(data);
 *
 * // Use:
 * byte[] hash = CryptoCache.sha256(data);
 *
 * // Instead of:
 * Signature sig = Signature.getInstance("SHA256withECDSA");
 * sig.initVerify(publicKey);
 * sig.update(data);
 * boolean valid = sig.verify(signature);
 *
 * // Use:
 * boolean valid = CryptoCache.verifyEs256(data, signature, publicKey);
 * }</pre>
 */
public final class CryptoCache {

    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    });

    private static final ThreadLocal<MessageDigest> SHA512 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512 not available", e);
        }
    });

    private static final ThreadLocal<Signature> ES256 = ThreadLocal.withInitial(() -> {
        try {
            return Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA256withECDSA not available", e);
        }
    });

    private CryptoCache() {
        // Utility class
    }

    /**
     * Computes the SHA-256 hash of the given data.
     *
     * @param data the data to hash
     * @return the 32-byte SHA-256 hash
     */
    public static byte[] sha256(byte[] data) {
        MessageDigest md = SHA256.get();
        md.reset();
        return md.digest(data);
    }

    /**
     * Computes the SHA-512 hash of the given data.
     *
     * @param data the data to hash
     * @return the 64-byte SHA-512 hash
     */
    public static byte[] sha512(byte[] data) {
        MessageDigest md = SHA512.get();
        md.reset();
        return md.digest(data);
    }

    /**
     * Verifies an ES256 (ECDSA with SHA-256 on P-256) signature.
     *
     * <p>Uses a thread-local Signature instance to avoid the overhead of
     * provider lookup on each verification.</p>
     *
     * @param data the data that was signed
     * @param signature the signature (typically in DER format for Java's Signature API)
     * @param publicKey the EC public key to verify against
     * @return true if the signature is valid, false otherwise
     * @throws InvalidKeyException if the public key is invalid
     * @throws SignatureException if the signature format is invalid
     */
    public static boolean verifyEs256(byte[] data, byte[] signature, PublicKey publicKey)
            throws InvalidKeyException, SignatureException {
        Signature sig = ES256.get();
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
