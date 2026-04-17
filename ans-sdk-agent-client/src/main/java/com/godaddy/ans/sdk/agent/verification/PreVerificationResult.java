package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.transparency.scitt.ScittPreVerifyResult;

import java.time.Instant;
import java.util.List;

/**
 * Result of pre-verification, containing expected state for post-handshake verification.
 *
 * <p>Pre-verification happens before the TLS handshake to gather expectations:</p>
 * <ul>
 *   <li><b>DANE</b>: Look up TLSA records and extract expected certificate data</li>
 *   <li><b>Badge</b>: Query transparency log for registered certificate fingerprints</li>
 *   <li><b>SCITT</b>: Extract and verify receipts/status tokens from HTTP headers</li>
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
 * @param scittPreVerifyResult the SCITT pre-verification result (null if not performed)
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
    ScittPreVerifyResult scittPreVerifyResult,
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
        // Note: compact constructor guarantees daneExpectations is never null
        return !daneExpectations.isEmpty();
    }

    /**
     * Returns true if Badge verification should be performed.
     *
     * @return true if badge fingerprints are available from transparency log
     */
    public boolean hasBadgeExpectation() {
        // Note: compact constructor guarantees badgeFingerprints is never null
        return !badgeFingerprints.isEmpty();
    }

    /**
     * Returns true if SCITT verification should be performed.
     *
     * @return true if SCITT artifacts are available
     */
    public boolean hasScittExpectation() {
        return scittPreVerifyResult != null && scittPreVerifyResult.isPresent();
    }

    /**
     * Returns true if SCITT pre-verification was successful.
     *
     * @return true if SCITT expectation is verified
     */
    public boolean scittPreVerifySucceeded() {
        return scittPreVerifyResult != null
            && scittPreVerifyResult.isPresent()
            && scittPreVerifyResult.expectation().isVerified();
    }

    /**
     * Returns a new PreVerificationResult with the SCITT result replaced.
     *
     * @param scittResult the new SCITT pre-verification result
     * @return a new PreVerificationResult with the updated SCITT result
     */
    public PreVerificationResult withScittResult(ScittPreVerifyResult scittResult) {
        return new PreVerificationResult(
            this.hostname,
            this.port,
            this.daneExpectations,
            this.daneDnsError,
            this.daneDnsErrorMessage,
            this.badgeFingerprints,
            this.badgePreVerifyFailed,
            this.badgeFailureReason,
            scittResult,
            this.timestamp
        );
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
        private ScittPreVerifyResult scittPreVerifyResult;

        private Builder(String hostname, int port) {
            this.hostname = hostname;
            this.port = port;
        }

        /**
         * Sets the DANE pre-verify result, extracting expectations and DNS error status.
         *
         * <p><b>This is the preferred method for setting DANE state.</b> It atomically sets
         * all DANE-related fields from a single result object, ensuring consistency.</p>
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
         * Sets the expected DANE expectations from TLSA records.
         *
         * <p><b>Note:</b> Prefer {@link #danePreVerifyResult(DaneVerifier.PreVerifyResult)} which
         * sets all DANE state atomically. This method exists primarily for testing scenarios
         * where constructing a full {@code PreVerifyResult} is inconvenient.</p>
         *
         * <p><b>Warning:</b> Calling this after {@link #danePreVerifyResult} will overwrite
         * the expectations but leave DNS error flags unchanged, potentially creating
         * inconsistent state.</p>
         *
         * @param expectations the TLSA expectations
         * @return this builder
         */
        public Builder daneExpectations(List<DaneTlsaVerifier.TlsaExpectation> expectations) {
            this.daneExpectations = expectations != null ? expectations : List.of();
            return this;
        }

        /**
         * Marks DANE pre-verification as failed due to DNS error.
         *
         * <p><b>Note:</b> Prefer {@link #danePreVerifyResult(DaneVerifier.PreVerifyResult)} which
         * sets all DANE state atomically. This method exists primarily for testing scenarios.</p>
         *
         * <p><b>Warning:</b> Calling this after {@link #danePreVerifyResult} will overwrite
         * the DNS error state but leave expectations unchanged, potentially creating
         * inconsistent state.</p>
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
         * Sets the SCITT pre-verification result.
         *
         * @param result the SCITT pre-verification result
         * @return this builder
         */
        public Builder scittPreVerifyResult(ScittPreVerifyResult result) {
            this.scittPreVerifyResult = result;
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
                scittPreVerifyResult,
                Instant.now()
            );
        }
    }

    @Override
    public String toString() {
        return String.format("PreVerificationResult{hostname='%s', port=%d, " +
            "hasDane=%s, hasBadge=%s, hasScitt=%s}",
            hostname, port, hasDaneExpectation(), hasBadgeExpectation(), hasScittExpectation());
    }
}
