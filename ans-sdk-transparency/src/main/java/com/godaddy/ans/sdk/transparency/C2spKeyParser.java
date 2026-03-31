package com.godaddy.ans.sdk.transparency;

import com.godaddy.ans.sdk.crypto.CryptoCache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Parser for C2SP note format public keys used by the SCITT transparency log.
 *
 * <p>C2SP note format: each line is {@code name+key_hash+base64_public_key}</p>
 */
final class C2spKeyParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(C2spKeyParser.class);

    /**
     * Maximum number of root keys to accept. Prevents DoS from unbounded key sets.
     */
    private static final int MAX_ROOT_KEYS = 20;

    /**
     * Cached KeyFactory instance. Thread-safe after initialization.
     */
    private static final KeyFactory EC_KEY_FACTORY;

    static {
        try {
            EC_KEY_FACTORY = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC algorithm not available", e);
        }
    }

    private C2spKeyParser() {
        // Utility class
    }

    /**
     * Parses public keys from the root-keys API response.
     *
     * <p>Format is C2SP note: each line is {@code name+key_hash+base64_public_key}</p>
     * <p>Example:</p>
     * <pre>
     * transparency.ans.godaddy.com+bb7ed8cf+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IAB...
     * transparency.ans.godaddy.com+cc8fe9d0+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IAB...
     * </pre>
     *
     * <p>Returns an immutable map keyed by hex key ID (4-byte SHA-256 of SPKI-DER) for O(1) lookup.</p>
     *
     * @param responseBody the raw response body (text/plain, C2SP note format)
     * @return immutable map of hex key ID to public key
     * @throws IllegalArgumentException if no valid keys found or too many keys
     */
    static Map<String, PublicKey> parsePublicKeysResponse(String responseBody) {
        Map<String, PublicKey> keys = new HashMap<>();
        List<String> parseErrors = new ArrayList<>();

        String[] lines = responseBody.split("\n");
        int lineNum = 0;
        for (String line : lines) {
            lineNum++;
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            // Check max keys limit
            if (keys.size() >= MAX_ROOT_KEYS) {
                LOGGER.warn("Reached max root keys limit ({}), ignoring remaining keys", MAX_ROOT_KEYS);
                break;
            }

            // C2SP format: name+key_hash+base64_key (limit split to 3 since base64 can contain '+')
            String[] parts = line.split("\\+", 3);
            if (parts.length != 3) {
                String error = String.format("Line %d: expected C2SP format (name+hash+key), got %d parts",
                    lineNum, parts.length);
                LOGGER.debug("Public key parse failed - {}", error);
                parseErrors.add(error);
                continue;
            }

            try {
                PublicKey key = decodePublicKey(parts[2].trim());
                String hexKeyId = computeHexKeyId(key);
                if (keys.containsKey(hexKeyId)) {
                    LOGGER.warn("Duplicate key ID {} at line {}, skipping", hexKeyId, lineNum);
                } else {
                    keys.put(hexKeyId, key);
                    LOGGER.debug("Parsed key with ID {} at line {}", hexKeyId, lineNum);
                }
            } catch (Exception e) {
                String error = String.format("Line %d: %s", lineNum, e.getMessage());
                LOGGER.debug("Public key parse failed - {}", error);
                parseErrors.add(error);
            }
        }

        if (keys.isEmpty()) {
            String errorDetail = parseErrors.isEmpty()
                ? "No parseable key lines found"
                : "Parse attempts failed: " + String.join("; ", parseErrors);
            throw new IllegalArgumentException("Could not parse any public keys from response. " + errorDetail);
        }

        return Map.copyOf(keys);
    }

    /**
     * Computes the hex key ID for a public key per C2SP specification.
     *
     * <p>The key ID is the first 4 bytes of SHA-256(SPKI-DER), where SPKI-DER
     * is the Subject Public Key Info DER encoding of the public key.</p>
     *
     * @param publicKey the public key
     * @return the 8-character hex key ID
     */
    static String computeHexKeyId(PublicKey publicKey) {
        byte[] spkiDer = publicKey.getEncoded();
        byte[] hash = CryptoCache.sha256(spkiDer);
        return HexFormat.of().formatHex(Arrays.copyOf(hash, 4));
    }

    /**
     * Decodes a base64-encoded public key.
     */
    private static PublicKey decodePublicKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        // C2SP note format includes a version byte prefix (0x02) before the SPKI-DER data.
        // We need to strip it to get valid SPKI-DER for Java's KeyFactory.
        // Detection: SPKI-DER starts with 0x30 (SEQUENCE tag), C2SP prefixed data starts with 0x02.
        if (keyBytes.length > 0 && keyBytes[0] == 0x02) {
            // Strip C2SP version byte (first byte)
            keyBytes = Arrays.copyOfRange(keyBytes, 1, keyBytes.length);
        }

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return EC_KEY_FACTORY.generatePublic(keySpec);
    }
}
