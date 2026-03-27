package com.godaddy.ans.sdk.agent.exception;

/**
 * Exception thrown when SCITT verification fails.
 *
 * <p>SCITT (Supply Chain Integrity, Transparency, and Trust) verification
 * can fail for various reasons including:</p>
 * <ul>
 *   <li>Invalid COSE_Sign1 signature on receipt or status token</li>
 *   <li>Invalid Merkle inclusion proof</li>
 *   <li>Expired or malformed status token</li>
 *   <li>Algorithm substitution attack (non-ES256 algorithm)</li>
 *   <li>Required public key not found or invalid</li>
 * </ul>
 */
public class ScittVerificationException extends TrustValidationException {

    private final FailureType failureType;

    /**
     * Types of SCITT verification failures.
     */
    public enum FailureType {
        /** SCITT headers required but not present in response */
        HEADERS_NOT_PRESENT,
        /** Failed to parse SCITT artifact (receipt or status token) */
        PARSE_ERROR,
        /** Algorithm in COSE header is not ES256 */
        INVALID_ALGORITHM,
        /** COSE_Sign1 signature verification failed */
        INVALID_SIGNATURE,
        /** Merkle tree inclusion proof is invalid */
        MERKLE_PROOF_INVALID,
        /** Status token has expired */
        TOKEN_EXPIRED,
        /** Required public key (TL or RA) not found */
        KEY_NOT_FOUND,
        /** Certificate fingerprint does not match expectations */
        FINGERPRINT_MISMATCH,
        /** Agent registration is revoked */
        AGENT_REVOKED,
        /** Agent status is not active */
        AGENT_INACTIVE,
        /** General verification error */
        VERIFICATION_ERROR
    }

    /**
     * Creates a new SCITT verification exception.
     *
     * @param message the error message
     * @param failureType the type of failure
     */
    public ScittVerificationException(String message, FailureType failureType) {
        super(message, mapToValidationReason(failureType));
        this.failureType = failureType;
    }

    /**
     * Creates a new SCITT verification exception with a cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param failureType the type of failure
     */
    public ScittVerificationException(String message, Throwable cause, FailureType failureType) {
        super(message, cause, null, mapToValidationReason(failureType));
        this.failureType = failureType;
    }

    /**
     * Creates a new SCITT verification exception with certificate info.
     *
     * @param message the error message
     * @param certificateSubject the subject of the certificate
     * @param failureType the type of failure
     */
    public ScittVerificationException(String message, String certificateSubject, FailureType failureType) {
        super(message, certificateSubject, mapToValidationReason(failureType));
        this.failureType = failureType;
    }

    /**
     * Returns the type of SCITT verification failure.
     *
     * @return the failure type
     */
    public FailureType getFailureType() {
        return failureType;
    }

    /**
     * Maps SCITT failure types to TrustValidationException reasons.
     */
    private static ValidationFailureReason mapToValidationReason(FailureType failureType) {
        if (failureType == null) {
            return ValidationFailureReason.UNKNOWN;
        }
        return switch (failureType) {
            case HEADERS_NOT_PRESENT, PARSE_ERROR, AGENT_INACTIVE, VERIFICATION_ERROR ->
                    ValidationFailureReason.UNKNOWN;
            case INVALID_ALGORITHM, MERKLE_PROOF_INVALID, INVALID_SIGNATURE, FINGERPRINT_MISMATCH ->
                    ValidationFailureReason.CHAIN_VALIDATION_FAILED;
            case TOKEN_EXPIRED -> ValidationFailureReason.EXPIRED;
            case KEY_NOT_FOUND -> ValidationFailureReason.TRUST_BUNDLE_LOAD_FAILED;
            case AGENT_REVOKED -> ValidationFailureReason.REVOKED;
        };
    }
}
