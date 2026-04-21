package com.godaddy.ans.sdk.transparency.scitt;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.crypto.CryptoCache;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Shared test helpers for SCITT-related tests.
 *
 * <p>Provides common cryptographic operations used across multiple SCITT test classes,
 * including EC key pair generation, key ID computation, and signature format conversion.</p>
 */
public final class ScittTestHelpers {

    private ScittTestHelpers() {
        // Utility class
    }

    /**
     * Generates an EC P-256 (secp256r1) key pair for use in tests.
     *
     * @return a new EC P-256 key pair
     * @throws Exception if key generation fails
     */
    public static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    /**
     * Converts a public key to a root keys map keyed by its hex key ID.
     *
     * <p>The key ID is computed as SHA-256(SPKI-DER)[0:4] formatted as a hex string,
     * per the C2SP specification.</p>
     *
     * @param publicKey the public key to convert
     * @return a map from hex key ID to the public key
     */
    public static Map<String, PublicKey> toRootKeys(PublicKey publicKey) {
        byte[] hash = CryptoCache.sha256(publicKey.getEncoded());
        String hexKeyId = CertificateUtils.bytesToHex(Arrays.copyOf(hash, 4));
        Map<String, PublicKey> map = new HashMap<>();
        map.put(hexKeyId, publicKey);
        return map;
    }

    /**
     * Computes the key ID for a public key per the C2SP specification.
     *
     * <p>The key ID is the first 4 bytes of SHA-256(SPKI-DER).</p>
     *
     * @param publicKey the public key
     * @return the 4-byte key ID
     * @throws Exception if digest computation fails
     */
    public static byte[] computeKeyId(PublicKey publicKey) throws Exception {
        byte[] hash = CryptoCache.sha256(publicKey.getEncoded());
        return Arrays.copyOf(hash, 4);
    }

    /**
     * Converts a DER-encoded ECDSA signature to IEEE P1363 format.
     *
     * <p>DER format: {@code SEQUENCE { INTEGER r, INTEGER s }}.
     * P1363 format: {@code r || s} (each 32 bytes for P-256, zero-padded).</p>
     *
     * @param derSignature the DER-encoded ECDSA signature
     * @return the 64-byte P1363-format signature
     */
    public static byte[] convertDerToP1363(byte[] derSignature) {
        // DER format: SEQUENCE { INTEGER r, INTEGER s }
        // P1363 format: r || s (each 32 bytes for P-256)
        byte[] p1363 = new byte[64];

        int offset = 2; // Skip SEQUENCE tag and length
        if (derSignature[1] == (byte) 0x81) {
            offset++;
        }

        // Parse r
        offset++; // Skip INTEGER tag
        int rLen = derSignature[offset++] & 0xFF;
        int rOffset = offset;
        if (rLen == 33 && derSignature[rOffset] == 0) {
            rOffset++;
            rLen--;
        }
        System.arraycopy(derSignature, rOffset, p1363, 32 - rLen, rLen);
        offset += (derSignature[offset - 1] & 0xFF);

        // Parse s
        offset++; // Skip INTEGER tag
        int sLen = derSignature[offset++] & 0xFF;
        int sOffset = offset;
        if (sLen == 33 && derSignature[sOffset] == 0) {
            sOffset++;
            sLen--;
        }
        System.arraycopy(derSignature, sOffset, p1363, 64 - sLen, sLen);

        return p1363;
    }

    /**
     * Converts a byte array to a lowercase hexadecimal string.
     *
     * @param bytes the bytes to convert
     * @return the hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
