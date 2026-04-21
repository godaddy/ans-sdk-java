package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.crypto.CryptoCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Utility class for TLSA (Transport Layer Security Authentication) operations.
 *
 * <p>This class provides shared constants and methods for DANE/TLSA verification,
 * used by both {@link DefaultDaneTlsaVerifier} and {@link DaneVerifier}.</p>
 *
 * <h2>TLSA Record Format</h2>
 * <p>TLSA records use the format: {@code Usage Selector MatchingType CertificateAssociationData}</p>
 * <ul>
 *   <li><b>Selector</b>: What part of the certificate to match (full cert or public key)</li>
 *   <li><b>MatchingType</b>: How to compare (exact, SHA-256, or SHA-512 hash)</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6698">RFC 6698 - DANE TLSA</a>
 */
public final class TlsaUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(TlsaUtils.class);

    // ==================== TLSA Selector Values ====================

    /**
     * Full certificate selector (DER-encoded).
     * The certificate association data matches the full certificate.
     */
    public static final int SELECTOR_FULL_CERT = 0;

    /**
     * SubjectPublicKeyInfo selector.
     * The certificate association data matches the public key (SPKI).
     */
    public static final int SELECTOR_SPKI = 1;

    // ==================== TLSA Matching Type Values ====================

    /**
     * Exact match - no hashing.
     * The certificate association data is the raw data (full cert or SPKI).
     */
    public static final int MATCH_EXACT = 0;

    /**
     * SHA-256 hash match.
     * The certificate association data is the SHA-256 hash of the selected data.
     */
    public static final int MATCH_SHA256 = 1;

    /**
     * SHA-512 hash match.
     * The certificate association data is the SHA-512 hash of the selected data.
     */
    public static final int MATCH_SHA512 = 2;

    private TlsaUtils() {
        // Utility class
    }

    /**
     * Computes certificate data for TLSA matching based on selector and matching type.
     *
     * <p>This method extracts the appropriate data from the certificate (full cert or SPKI)
     * and optionally hashes it according to the matching type.</p>
     *
     * @param cert the X.509 certificate
     * @param selector the TLSA selector (0 = full cert, 1 = SPKI)
     * @param matchingType the TLSA matching type (0 = exact, 1 = SHA-256, 2 = SHA-512)
     * @return the computed certificate data, or null if selector/matchingType is unknown
     * @throws CertificateEncodingException if the certificate cannot be encoded
     */
    public static byte[] computeCertificateData(X509Certificate cert, int selector, int matchingType)
            throws CertificateEncodingException {

        // Extract data based on selector
        byte[] data;
        if (selector == SELECTOR_FULL_CERT) {
            data = cert.getEncoded();
        } else if (selector == SELECTOR_SPKI) {
            data = cert.getPublicKey().getEncoded();
        } else {
            LOGGER.warn("Unknown TLSA selector: {}", selector);
            return null;
        }

        // Apply matching type (hash or exact)
        return switch (matchingType) {
            case MATCH_EXACT -> data;
            case MATCH_SHA256 -> CryptoCache.sha256(data);
            case MATCH_SHA512 -> CryptoCache.sha512(data);
            default -> {
                LOGGER.warn("Unknown TLSA matching type: {}", matchingType);
                yield null;
            }
        };
    }

    /**
     * Describes the match type for logging and display purposes.
     *
     * @param selector the TLSA selector
     * @param matchingType the TLSA matching type
     * @return a human-readable description (e.g., "SPKI-SHA-256")
     */
    public static String describeMatchType(int selector, int matchingType) {
        String selectorName = selector == SELECTOR_SPKI ? "SPKI" : "FullCert";
        String matchName = switch (matchingType) {
            case MATCH_SHA256 -> "SHA-256";
            case MATCH_SHA512 -> "SHA-512";
            default -> "Exact";
        };
        return selectorName + "-" + matchName;
    }

    /**
     * Converts a byte array to a lowercase hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return the hex string, or "null" if bytes is null
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        return CertificateUtils.bytesToHex(bytes);
    }
}