package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.exception.AnsException;

/**
 * Exception thrown when certificate trust validation fails.
 *
 * <p>This exception can be caused by:</p>
 * <ul>
 *   <li>Certificate not signed by a trusted CA</li>
 *   <li>Certificate chain validation failure</li>
 *   <li>Expired or not-yet-valid certificates</li>
 *   <li>Certificate revoked</li>
 *   <li>ANSName mismatch in certificate SAN</li>
 * </ul>
 */
public class TrustValidationException extends AnsException {

    private final String certificateSubject;
    private final ValidationFailureReason reason;

    /**
     * Creates a new exception with the specified message.
     *
     * @param message the error message
     */
    public TrustValidationException(String message) {
        this(message, null, null, null);
    }

    /**
     * Creates a new exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public TrustValidationException(String message, Throwable cause) {
        this(message, cause, null, null);
    }

    /**
     * Creates a new exception with the specified message and reason.
     *
     * @param message the error message
     * @param reason the validation failure reason
     */
    public TrustValidationException(String message, ValidationFailureReason reason) {
        this(message, null, null, reason);
    }

    /**
     * Creates a new exception with the specified message, certificate subject, and reason.
     *
     * @param message the error message
     * @param certificateSubject the subject of the failed certificate
     * @param reason the validation failure reason
     */
    public TrustValidationException(String message, String certificateSubject, ValidationFailureReason reason) {
        this(message, null, certificateSubject, reason);
    }

    /**
     * Creates a new exception with all parameters.
     *
     * @param message the error message
     * @param cause the underlying cause
     * @param certificateSubject the subject of the failed certificate
     * @param reason the validation failure reason
     */
    public TrustValidationException(String message, Throwable cause, String certificateSubject,
                                    ValidationFailureReason reason) {
        super(message, cause, null);
        this.certificateSubject = certificateSubject;
        this.reason = reason;
    }

    /**
     * Returns the subject of the certificate that failed validation.
     *
     * @return the certificate subject, or null if not available
     */
    public String getCertificateSubject() {
        return certificateSubject;
    }

    /**
     * Returns the reason for the validation failure.
     *
     * @return the validation failure reason, or null if not specified
     */
    public ValidationFailureReason getReason() {
        return reason;
    }

    /**
     * Enumeration of possible trust validation failure reasons.
     */
    public enum ValidationFailureReason {
        /**
         * Certificate is not signed by a trusted CA.
         */
        UNTRUSTED_CA,

        /**
         * Certificate chain validation failed.
         */
        CHAIN_VALIDATION_FAILED,

        /**
         * Certificate has expired.
         */
        EXPIRED,

        /**
         * Certificate is not yet valid.
         */
        NOT_YET_VALID,

        /**
         * Certificate has been revoked.
         */
        REVOKED,

        /**
         * ANSName in certificate SAN does not match expected value.
         */
        ANS_NAME_MISMATCH,

        /**
         * Certificate is missing required extensions.
         */
        MISSING_EXTENSIONS,

        /**
         * Trust bundle failed to load.
         */
        TRUST_BUNDLE_LOAD_FAILED,

        /**
         * Unknown validation failure.
         */
        UNKNOWN
    }
}