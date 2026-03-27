package com.godaddy.ans.sdk.transparency.scitt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Verifies that fetched metadata matches expected hashes from SCITT status tokens.
 *
 * <p>When an agent endpoint includes a metadataUrl, the status token contains
 * a hash of that metadata. After fetching the metadata, this verifier confirms
 * it hasn't been tampered with.</p>
 *
 * <h2>Hash Format</h2>
 * <p>Hashes are formatted as {@code SHA256:<64-hex-chars>}</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * byte[] metadataBytes = fetchMetadata(metadataUrl);
 * String expectedHash = statusToken.metadataHashes().get("a2a");
 *
 * if (!MetadataHashVerifier.verify(metadataBytes, expectedHash)) {
 *     throw new SecurityException("Metadata hash mismatch");
 * }
 * }</pre>
 */
public final class MetadataHashVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetadataHashVerifier.class);

    /**
     * Pattern for metadata hash format: SHA256:&lt;64 hex chars&gt;
     */
    private static final Pattern HASH_PATTERN = Pattern.compile("^SHA256:([a-f0-9]{64})$", Pattern.CASE_INSENSITIVE);

    private MetadataHashVerifier() {
        // Utility class
    }

    /**
     * Verifies that the metadata bytes match the expected hash.
     *
     * @param metadataBytes the fetched metadata content
     * @param expectedHash the expected hash in format {@code SHA256:<hex>}
     * @return true if the hash matches
     */
    public static boolean verify(byte[] metadataBytes, String expectedHash) {
        Objects.requireNonNull(metadataBytes, "metadataBytes cannot be null");
        Objects.requireNonNull(expectedHash, "expectedHash cannot be null");

        // Parse expected hash
        Matcher matcher = HASH_PATTERN.matcher(expectedHash);
        if (!matcher.matches()) {
            LOGGER.warn("Invalid hash format: {}", expectedHash);
            return false;
        }

        String expectedHex = matcher.group(1).toLowerCase();

        try {
            // Compute actual hash
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] actualHash = md.digest(metadataBytes);
            String actualHex = bytesToHex(actualHash);

            // SECURITY: Use constant-time comparison
            boolean matches = MessageDigest.isEqual(
                actualHex.getBytes(),
                expectedHex.getBytes()
            );

            if (!matches) {
                LOGGER.warn("Metadata hash mismatch: expected {}, got SHA256:{}",
                    expectedHash, actualHex);
            }

            return matches;

        } catch (Exception e) {
            LOGGER.error("Error computing metadata hash: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Computes the hash of metadata bytes in the expected format.
     *
     * @param metadataBytes the metadata content
     * @return the hash in format {@code SHA256:<hex>}
     */
    public static String computeHash(byte[] metadataBytes) {
        Objects.requireNonNull(metadataBytes, "metadataBytes cannot be null");

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(metadataBytes);
            return "SHA256:" + bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Validates that a hash string is in the expected format.
     *
     * @param hash the hash string to validate
     * @return true if the format is valid
     */
    public static boolean isValidHashFormat(String hash) {
        if (hash == null) {
            return false;
        }
        return HASH_PATTERN.matcher(hash).matches();
    }

    /**
     * Extracts the hex portion from a hash string.
     *
     * @param hash the hash string in format {@code SHA256:<hex>}
     * @return the hex portion, or null if format is invalid
     */
    public static String extractHex(String hash) {
        if (hash == null) {
            return null;
        }
        Matcher matcher = HASH_PATTERN.matcher(hash);
        if (matcher.matches()) {
            return matcher.group(1).toLowerCase();
        }
        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
