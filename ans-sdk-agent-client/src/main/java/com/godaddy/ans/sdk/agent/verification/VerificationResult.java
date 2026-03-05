package com.godaddy.ans.sdk.agent.verification;

/**
 * Result of a verification operation (DANE or Badge).
 *
 * <p>This record provides a structured way to return verification results
 * without throwing exceptions, enabling verification to happen outside
 * the TLS handshake.</p>
 *
 * @param status the verification status
 * @param type the type of verification that was performed
 * @param reason explanation for the result (failure reason or success details)
 * @param actualFingerprint the fingerprint of the certificate that was verified
 * @param expectedFingerprint the fingerprint that was expected (from DANE or transparency log)
 */
public record VerificationResult(
    Status status,
    VerificationType type,
    String reason,
    String actualFingerprint,
    String expectedFingerprint
) {

    /**
     * Verification status.
     */
    public enum Status {
        /** Verification succeeded - fingerprints match */
        SUCCESS,
        /** Verification failed - fingerprints do not match */
        MISMATCH,
        /** Verification skipped - no record/registration found (advisory mode) */
        NOT_FOUND,
        /** Verification error - unable to perform verification */
        ERROR
    }

    /**
     * Type of verification.
     */
    public enum VerificationType {
        /** DANE/TLSA DNS record verification */
        DANE,
        /** ANS transparency log badge verification (proof of registration) */
        BADGE,
        /** PKI-only verification (no additional ANS verification performed) */
        PKI_ONLY
    }

    /**
     * Creates a successful verification result.
     *
     * @param type the verification type
     * @param fingerprint the matching fingerprint
     * @return a success result
     */
    public static VerificationResult success(VerificationType type, String fingerprint) {
        return new VerificationResult(Status.SUCCESS, type, "Verification successful", fingerprint, fingerprint);
    }

    /**
     * Creates a successful verification result with details.
     *
     * @param type the verification type
     * @param fingerprint the matching fingerprint
     * @param reason additional details about the success
     * @return a success result
     */
    public static VerificationResult success(VerificationType type, String fingerprint, String reason) {
        return new VerificationResult(Status.SUCCESS, type, reason, fingerprint, fingerprint);
    }

    /**
     * Creates a mismatch verification result.
     *
     * @param type the verification type
     * @param actual the actual certificate fingerprint
     * @param expected the expected fingerprint
     * @return a mismatch result
     */
    public static VerificationResult mismatch(VerificationType type, String actual, String expected) {
        String reason = String.format("Certificate fingerprint mismatch: expected %s, got %s",
            truncateFingerprint(expected), truncateFingerprint(actual));
        return new VerificationResult(Status.MISMATCH, type, reason, actual, expected);
    }

    /**
     * Creates a not-found verification result.
     *
     * @param type the verification type
     * @param reason explanation of what was not found
     * @return a not-found result
     */
    public static VerificationResult notFound(VerificationType type, String reason) {
        return new VerificationResult(Status.NOT_FOUND, type, reason, null, null);
    }

    /**
     * Creates an error verification result.
     *
     * @param type the verification type
     * @param reason the error description
     * @return an error result
     */
    public static VerificationResult error(VerificationType type, String reason) {
        return new VerificationResult(Status.ERROR, type, reason, null, null);
    }

    /**
     * Creates an error verification result from an exception.
     *
     * @param type the verification type
     * @param cause the exception that caused the error
     * @return an error result
     */
    public static VerificationResult error(VerificationType type, Throwable cause) {
        String reason = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
        return new VerificationResult(Status.ERROR, type, reason, null, null);
    }

    /**
     * Creates a result indicating no additional verification was performed.
     *
     * <p>This is used when only PKI/TLS validation occurred (no DANE or Badge
     * verification). This is semantically clearer than returning a SUCCESS with null
     * fingerprints for a verification type that wasn't actually checked.</p>
     *
     * @param reason explanation of why verification was skipped
     * @return a not-found result with PKI_ONLY type
     */
    public static VerificationResult skipped(String reason) {
        return new VerificationResult(Status.NOT_FOUND, VerificationType.PKI_ONLY, reason, null, null);
    }

    /**
     * Returns true if verification was successful.
     *
     * @return true if status is SUCCESS
     */
    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }

    /**
     * Returns true if verification failed and should block the connection.
     *
     * @return true if status is MISMATCH or ERROR
     */
    public boolean shouldFail() {
        return status == Status.MISMATCH || status == Status.ERROR;
    }

    /**
     * Returns true if verification found no record but didn't fail.
     *
     * @return true if status is NOT_FOUND
     */
    public boolean isNotFound() {
        return status == Status.NOT_FOUND;
    }

    private static String truncateFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.length() <= 16) {
            return fingerprint;
        }
        return fingerprint.substring(0, 16) + "...";
    }

    @Override
    public String toString() {
        return String.format("VerificationResult{type=%s, status=%s, reason='%s'}",
            type, status, reason);
    }
}
