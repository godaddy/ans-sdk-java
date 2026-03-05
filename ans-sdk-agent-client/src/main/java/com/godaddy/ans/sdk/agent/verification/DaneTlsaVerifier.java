package com.godaddy.ans.sdk.agent.verification;

/**
 * Interface for DANE/TLSA DNS record verification.
 *
 * <p>DANE (DNS-Based Authentication of Named Entities) allows binding TLS certificates
 * to DNS records, providing an additional layer of trust verification beyond traditional
 * Certificate Authority (CA) validation.</p>
 *
 * <h2>TLSA Record Format</h2>
 * <p>TLSA records are published at {@code _port._tcp.hostname} and contain:</p>
 * <ul>
 *   <li><b>Certificate Usage</b>: How the certificate should be validated (0-3)</li>
 *   <li><b>Selector</b>: What part of the certificate to match (0=full cert, 1=public key)</li>
 *   <li><b>Matching Type</b>: How to match (0=exact, 1=SHA-256, 2=SHA-512)</li>
 *   <li><b>Certificate Association Data</b>: The hash or certificate data</li>
 * </ul>
 *
 * <h2>Example TLSA Record</h2>
 * <pre>
 * _443._tcp.example.com. IN TLSA 3 1 1 a1b2c3d4...
 * </pre>
 * <p>This means: Usage 3 (domain-issued cert), Selector 1 (public key only),
 * Matching Type 1 (SHA-256 hash).</p>
 *
 * <h2>Integration with ANS Trust Tiers</h2>
 * <ul>
 *   <li><b>Bronze</b>: No DANE verification</li>
 *   <li><b>Silver</b>: TLSA record must exist and match server certificate</li>
 *   <li><b>Gold</b>: Silver + Trust-on-First-Use with change detection</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6698">RFC 6698 - DANE Protocol</a>
 */
public interface DaneTlsaVerifier {

    /**
     * Represents an expected TLSA record from DNS.
     *
     * <p>This record holds the raw TLSA data needed for certificate verification
     * without requiring a TLS connection to the server.</p>
     *
     * @param selector the selector (0=full cert, 1=SPKI/public key)
     * @param matchingType the matching type (0=exact, 1=SHA-256, 2=SHA-512)
     * @param expectedData the certificate association data from the TLSA record
     */
    record TlsaExpectation(int selector, int matchingType, byte[] expectedData) {
        /**
         * Compact constructor for defensive copying.
         */
        public TlsaExpectation {
            expectedData = expectedData != null ? expectedData.clone() : null;
        }

        /**
         * Returns the expected data (defensively copied).
         */
        @Override
        public byte[] expectedData() {
            return expectedData != null ? expectedData.clone() : null;
        }
    }

    /**
     * Result of TLSA verification.
     *
     * @param verified whether verification succeeded
     * @param matchType description of the match type (e.g., "SPKI-SHA256")
     * @param reason the reason for failure, or null if successful
     * @param certificateData the matched certificate/key data
     */
    record TlsaResult(
        boolean verified,
        String matchType,
        String reason,
        byte[] certificateData
    ) {
        /**
         * Compact constructor for defensive copying of byte array.
         */
        public TlsaResult {
            certificateData = certificateData != null ? certificateData.clone() : null;
        }

        /**
         * Creates a successful verification result.
         *
         * @param matchType description of the match type (e.g., "SPKI-SHA256")
         * @param certificateData the matched certificate/key data
         * @return a successful result
         */
        public static TlsaResult success(String matchType, byte[] certificateData) {
            return new TlsaResult(true, matchType, null, certificateData);
        }

        /**
         * Creates a failed verification result.
         *
         * @param reason the reason for failure
         * @return a failed result
         */
        public static TlsaResult failure(String reason) {
            return new TlsaResult(false, null, reason, null);
        }

        /**
         * Creates a result indicating no TLSA record exists.
         *
         * @return a result indicating no TLSA record
         */
        public static TlsaResult noRecord() {
            return new TlsaResult(false, null, "No TLSA record found", null);
        }

        /**
         * Creates a result indicating DANE verification was skipped.
         *
         * <p>This is used when DANE policy is DISABLED or when verification
         * is intentionally bypassed.</p>
         *
         * @param reason the reason for skipping (e.g., "DANE verification disabled")
         * @return a skipped result
         */
        public static TlsaResult skipped(String reason) {
            return new TlsaResult(false, "SKIPPED", reason, null);
        }

        /**
         * Returns true if verification was skipped (not attempted).
         *
         * @return true if this result represents a skip
         */
        public boolean isSkipped() {
            return "SKIPPED".equals(matchType);
        }

        /**
         * Returns the certificate/key data that was matched (defensively copied).
         *
         * @return the certificate data, or null if verification failed
         */
        @Override
        public byte[] certificateData() {
            return certificateData != null ? certificateData.clone() : null;
        }

        @Override
        public String toString() {
            if (verified) {
                return "TlsaResult{verified=true, matchType='" + matchType + "'}";
            } else {
                return "TlsaResult{verified=false, reason='" + reason + "'}";
            }
        }
    }

    /**
     * Verifies that the server's TLS certificate matches the TLSA DNS record.
     *
     * <p>This method:</p>
     * <ol>
     *   <li>Queries the TLSA record at {@code _port._tcp.hostname}</li>
     *   <li>Connects to the server and retrieves its TLS certificate</li>
     *   <li>Compares the certificate/key against the TLSA record</li>
     * </ol>
     *
     * @param hostname the hostname to verify
     * @param port the port number (typically 443)
     * @return the verification result
     */
    TlsaResult verifyTlsa(String hostname, int port);

    /**
     * Checks if a TLSA record exists for the given hostname and port.
     *
     * <p>This is a lightweight check that only queries DNS, without connecting
     * to the server.</p>
     *
     * @param hostname the hostname
     * @param port the port number
     * @return true if a TLSA record exists
     */
    boolean hasTlsaRecord(String hostname, int port);

    /**
     * Gets TLSA record expectations from DNS without connecting to the server.
     *
     * <p>This method performs a DNS-only operation to retrieve TLSA records.
     * It is designed for the pre-verification phase where you need the expected
     * certificate data before establishing a TLS connection.</p>
     *
     * <p>Unlike {@link #verifyTlsa}, this method does NOT:</p>
     * <ul>
     *   <li>Connect to the server</li>
     *   <li>Retrieve the server's TLS certificate</li>
     *   <li>Perform certificate matching</li>
     * </ul>
     *
     * @param hostname the hostname to look up
     * @param port the port number (typically 443)
     * @return list of TLSA expectations (empty if no records found or DANE disabled)
     * @throws Exception if DNS query fails or DNSSEC validation fails
     */
    java.util.List<TlsaExpectation> getTlsaExpectations(String hostname, int port) throws Exception;
}