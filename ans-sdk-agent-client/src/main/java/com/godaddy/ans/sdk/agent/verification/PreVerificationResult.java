package com.godaddy.ans.sdk.agent.verification;

import java.time.Instant;
import java.util.List;

/**
 * Result of pre-verification, containing expected state for post-handshake verification.
 *
 * <p>Pre-verification happens before the TLS handshake to gather expectations:</p>
 * <ul>
 *   <li><b>DANE</b>: Look up TLSA records and extract expected certificate data</li>
 *   <li><b>Badge</b>: Query transparency log for registered certificate fingerprints</li>
 * </ul>
 *
 * <p>After the TLS handshake completes, the actual server certificate is compared
 * against these pre-verified expectations.</p>
 *
 * <p>During version rotation, multiple badge records may exist with different fingerprints.
 * The certificate is valid if it matches ANY of the expected fingerprints from
 * ACTIVE or DEPRECATED registrations.</p>
 *
 * @param hostname the hostname that was pre-verified
 * @param port the port used for verification
 * @param daneExpectations list of TLSA expectations from DNS (empty if no records)
 * @param daneDnsError true if DNS lookup for TLSA records failed
 * @param daneDnsErrorMessage the DNS error message if lookup failed (null otherwise)
 * @param badgeFingerprints expected fingerprints from transparency log (empty if not registered)
 * @param badgePreVerifyFailed true if badge pre-verification failed (e.g., revoked/expired)
 * @param badgeFailureReason the reason for badge pre-verification failure (null if not failed)
 * @param timestamp when the pre-verification was performed
 */
public record PreVerificationResult(
    String hostname,
    int port,
    List<DaneTlsaVerifier.TlsaExpectation> daneExpectations,
    boolean daneDnsError,
    String daneDnsErrorMessage,
    List<String> badgeFingerprints,
    boolean badgePreVerifyFailed,
    String badgeFailureReason,
    Instant timestamp
) {

    /**
     * Compact constructor for defensive copying.
     */
    public PreVerificationResult {
        daneExpectations = daneExpectations != null ? List.copyOf(daneExpectations) : List.of();
        badgeFingerprints = badgeFingerprints != null ? List.copyOf(badgeFingerprints) : List.of();
    }

    /**
     * Creates a builder for PreVerificationResult.
     *
     * @param hostname the hostname being verified
     * @param port the port number
     * @return a new builder
     */
    public static Builder builder(String hostname, int port) {
        return new Builder(hostname, port);
    }

    /**
     * Returns true if DANE verification should be performed.
     *
     * @return true if DANE expectations are available
     */
    public boolean hasDaneExpectation() {
        return daneExpectations != null && !daneExpectations.isEmpty();
    }

    /**
     * Returns true if Badge verification should be performed.
     *
     * @return true if badge fingerprints are available from transparency log
     */
    public boolean hasBadgeExpectation() {
        return badgeFingerprints != null && !badgeFingerprints.isEmpty();
    }

    /**
     * Builder for PreVerificationResult.
     */
    public static class Builder {
        private final String hostname;
        private final int port;
        private List<DaneTlsaVerifier.TlsaExpectation> daneExpectations = List.of();
        private boolean daneDnsError;
        private String daneDnsErrorMessage;
        private List<String> badgeFingerprints = List.of();
        private boolean badgePreVerifyFailed;
        private String badgeFailureReason;

        private Builder(String hostname, int port) {
            this.hostname = hostname;
            this.port = port;
        }

        /**
         * Sets the expected DANE expectations from TLSA records.
         *
         * @param expectations the TLSA expectations
         * @return this builder
         */
        public Builder daneExpectations(List<DaneTlsaVerifier.TlsaExpectation> expectations) {
            this.daneExpectations = expectations != null ? expectations : List.of();
            return this;
        }

        /**
         * Sets the DANE pre-verify result, extracting expectations and DNS error status.
         *
         * @param result the DANE pre-verify result
         * @return this builder
         */
        public Builder danePreVerifyResult(DaneVerifier.PreVerifyResult result) {
            if (result != null) {
                this.daneExpectations = result.expectations();
                this.daneDnsError = result.isDnsError();
                this.daneDnsErrorMessage = result.errorMessage();
            }
            return this;
        }

        /**
         * Marks DANE pre-verification as failed due to DNS error.
         *
         * @param errorMessage the DNS error message
         * @return this builder
         */
        public Builder daneDnsError(String errorMessage) {
            this.daneDnsError = true;
            this.daneDnsErrorMessage = errorMessage;
            return this;
        }

        /**
         * Sets the expected badge fingerprints from transparency log.
         *
         * <p>During version rotation, multiple badge records may exist with different
         * fingerprints. The certificate is valid if it matches ANY of the expected
         * fingerprints.</p>
         *
         * @param fingerprints the expected fingerprints
         * @return this builder
         */
        public Builder badgeFingerprints(List<String> fingerprints) {
            this.badgeFingerprints = fingerprints != null ? fingerprints : List.of();
            return this;
        }

        /**
         * Marks badge pre-verification as failed (e.g., revoked/expired registration).
         *
         * @param reason the failure reason
         * @return this builder
         */
        public Builder badgePreVerifyFailed(String reason) {
            this.badgePreVerifyFailed = true;
            this.badgeFailureReason = reason;
            return this;
        }

        /**
         * Builds the PreVerificationResult.
         *
         * @return the built result
         */
        public PreVerificationResult build() {
            return new PreVerificationResult(
                hostname,
                port,
                daneExpectations,
                daneDnsError,
                daneDnsErrorMessage,
                badgeFingerprints,
                badgePreVerifyFailed,
                badgeFailureReason,
                Instant.now()
            );
        }
    }

    @Override
    public String toString() {
        return String.format("PreVerificationResult{hostname='%s', port=%d, " +
            "hasDane=%s, hasBadge=%s}",
            hostname, port, hasDaneExpectation(), hasBadgeExpectation());
    }
}
