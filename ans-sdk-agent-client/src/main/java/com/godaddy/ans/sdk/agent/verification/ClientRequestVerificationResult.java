package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.transparency.scitt.ScittReceipt;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Result of client request verification.
 *
 * <p>Contains the outcome of verifying an incoming client request, including
 * the extracted agent identity, SCITT artifacts, and any errors encountered.</p>
 *
 * @param verified true if the client was successfully verified
 * @param agentId the agent ID from the status token (null if verification failed)
 * @param statusToken the parsed status token (null if not present or failed to parse)
 * @param receipt the parsed SCITT receipt (null if not present or failed to parse)
 * @param clientCertificate the client certificate that was verified
 * @param errors list of error messages (empty if verification succeeded)
 * @param policyUsed the verification policy that was applied
 * @param verificationDuration how long verification took
 */
public record ClientRequestVerificationResult(
    boolean verified,
    String agentId,
    StatusToken statusToken,
    ScittReceipt receipt,
    X509Certificate clientCertificate,
    List<String> errors,
    VerificationPolicy policyUsed,
    Duration verificationDuration
) {

    /**
     * Compact constructor for defensive copying.
     */
    public ClientRequestVerificationResult {
        Objects.requireNonNull(errors, "errors cannot be null");
        Objects.requireNonNull(policyUsed, "policyUsed cannot be null");
        Objects.requireNonNull(verificationDuration, "verificationDuration cannot be null");
        errors = List.copyOf(errors);
    }

    /**
     * Returns true if SCITT artifacts (receipt and status token) are present.
     *
     * @return true if both receipt and status token are available
     */
    public boolean hasScittArtifacts() {
        return receipt != null && statusToken != null;
    }

    /**
     * Returns true if only the status token is present.
     *
     * @return true if status token is available but receipt is not
     */
    public boolean hasStatusTokenOnly() {
        return statusToken != null && receipt == null;
    }

    /**
     * Returns true if any SCITT artifact is present.
     *
     * @return true if receipt or status token is available
     */
    public boolean hasAnyScittArtifact() {
        return receipt != null || statusToken != null;
    }

    /**
     * Returns true if the client certificate was verified against the status token.
     *
     * <p>This indicates the certificate fingerprint matched one of the valid
     * identity certificate fingerprints in the status token.</p>
     *
     * @return true if certificate was trusted via SCITT verification
     */
    public boolean isCertificateTrusted() {
        return verified && statusToken != null;
    }

    /**
     * Creates a successful verification result.
     *
     * @param agentId the verified agent ID
     * @param statusToken the verified status token
     * @param receipt the verified receipt
     * @param clientCertificate the client certificate
     * @param policy the policy that was used
     * @param duration how long verification took
     * @return a successful result
     */
    public static ClientRequestVerificationResult success(
            String agentId,
            StatusToken statusToken,
            ScittReceipt receipt,
            X509Certificate clientCertificate,
            VerificationPolicy policy,
            Duration duration) {
        return new ClientRequestVerificationResult(
            true,
            agentId,
            statusToken,
            receipt,
            clientCertificate,
            List.of(),
            policy,
            duration
        );
    }

    /**
     * Creates a failed verification result.
     *
     * @param errors the error messages
     * @param statusToken the status token if parsed (may be null)
     * @param receipt the receipt if parsed (may be null)
     * @param clientCertificate the client certificate
     * @param policy the policy that was used
     * @param duration how long verification took
     * @return a failed result
     */
    public static ClientRequestVerificationResult failure(
            List<String> errors,
            StatusToken statusToken,
            ScittReceipt receipt,
            X509Certificate clientCertificate,
            VerificationPolicy policy,
            Duration duration) {
        String agentId = statusToken != null ? statusToken.agentId() : null;
        return new ClientRequestVerificationResult(
            false,
            agentId,
            statusToken,
            receipt,
            clientCertificate,
            errors,
            policy,
            duration
        );
    }

    /**
     * Creates a failed verification result with a single error.
     *
     * @param error the error message
     * @param clientCertificate the client certificate
     * @param policy the policy that was used
     * @param duration how long verification took
     * @return a failed result
     */
    public static ClientRequestVerificationResult failure(
            String error,
            X509Certificate clientCertificate,
            VerificationPolicy policy,
            Duration duration) {
        return failure(
            List.of(error),
            null,
            null,
            clientCertificate,
            policy,
            duration
        );
    }

    @Override
    public String toString() {
        if (verified) {
            return String.format(
                "ClientRequestVerificationResult{verified=true, agentId='%s', duration=%s}",
                agentId, verificationDuration);
        } else {
            return String.format(
                "ClientRequestVerificationResult{verified=false, errors=%s, duration=%s}",
                errors, verificationDuration);
        }
    }
}
