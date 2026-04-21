package com.godaddy.ans.sdk.agent.verification;

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
 * Shared test helpers for key generation and root key construction across verification tests.
 */
public final class VerificationTestHelpers {

    private VerificationTestHelpers() {
        // utility class
    }

    /**
     * Generates an EC key pair using P-256 (secp256r1).
     *
     * @return a fresh {@link KeyPair}
     */
    public static KeyPair generateEcKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC key pair", e);
        }
    }

    /**
     * Converts a {@link PublicKey} into a root-keys map keyed by a 4-byte hex key ID
     * derived from SHA-256(SPKI-DER).
     *
     * @param publicKey the public key to index
     * @return a single-entry map of hex key ID to public key
     */
    public static Map<String, PublicKey> toRootKeys(PublicKey publicKey) {
        byte[] hash = CryptoCache.sha256(publicKey.getEncoded());
        String hexKeyId = CertificateUtils.bytesToHex(Arrays.copyOf(hash, 4));
        Map<String, PublicKey> map = new HashMap<>();
        map.put(hexKeyId, publicKey);
        return map;
    }
}
