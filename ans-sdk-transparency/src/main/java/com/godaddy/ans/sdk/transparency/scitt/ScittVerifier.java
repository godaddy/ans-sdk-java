package com.godaddy.ans.sdk.transparency.scitt;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Interface for SCITT (Supply Chain Integrity, Transparency, and Trust) verification.
 *
 * <p>SCITT verification replaces live transparency log queries with cryptographic
 * proof verification. Artifacts (receipt + status token) are delivered via HTTP
 * headers and verified locally using cached public keys.</p>
 *
 * <h2>Verification Flow</h2>
 * <ol>
 *   <li>Parse receipt and status token from HTTP headers</li>
 *   <li>Verify receipt signature using TL public key</li>
 *   <li>Verify Merkle inclusion proof in receipt</li>
 *   <li>Verify status token signature using RA public key</li>
 *   <li>Check status token expiry (with clock skew tolerance)</li>
 *   <li>Extract expected certificate fingerprints</li>
 * </ol>
 *
 * <h2>Post-Verification</h2>
 * <p>After TLS handshake, compare actual server certificate against
 * the expected fingerprints from the status token.</p>
 */
public interface ScittVerifier {

    /**
     * Verifies SCITT artifacts and extracts expectations.
     *
     * <p>Both the receipt and status token are signed by the same transparency log key.
     * The correct key is selected from the map by matching the key ID in the artifact
     * header.</p>
     *
     * @param receipt the parsed SCITT receipt
     * @param token the parsed status token
     * @param rootKeys the root public keys, keyed by hex key ID (4-byte SHA-256 of SPKI-DER)
     * @return the verification expectation with expected certificate fingerprints
     */
    ScittExpectation verify(
        ScittReceipt receipt,
        StatusToken token,
        Map<String, PublicKey> rootKeys
    );

    /**
     * Verifies that the server certificate matches the SCITT expectation.
     *
     * <p>This should be called after the TLS handshake completes to compare
     * the actual server certificate against the expected fingerprints.</p>
     *
     * @param hostname the hostname that was connected to
     * @param serverCert the server certificate from TLS handshake
     * @param expectation the expectation from {@link #verify}
     * @return the verification result
     */
    ScittVerificationResult postVerify(
        String hostname,
        X509Certificate serverCert,
        ScittExpectation expectation
    );

    /**
     * Result of SCITT post-verification.
     *
     * @param success true if server certificate matches expectations
     * @param actualFingerprint the fingerprint of the server certificate
     * @param matchedFingerprint the expected fingerprint that matched (null if no match)
     * @param failureReason reason for failure (null if successful)
     */
    record ScittVerificationResult(
        boolean success,
        String actualFingerprint,
        String matchedFingerprint,
        String failureReason
    ) {
        /**
         * Creates a successful result.
         */
        public static ScittVerificationResult success(String fingerprint) {
            return new ScittVerificationResult(true, fingerprint, fingerprint, null);
        }

        /**
         * Creates a mismatch result.
         */
        public static ScittVerificationResult mismatch(String actual, String reason) {
            return new ScittVerificationResult(false, actual, null, reason);
        }

        /**
         * Creates an error result.
         */
        public static ScittVerificationResult error(String reason) {
            return new ScittVerificationResult(false, null, null, reason);
        }
    }
}
