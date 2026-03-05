package com.godaddy.ans.sdk.agent;

/**
 * Determines how a verification method behaves on success or failure.
 *
 * <p>Each verification type (DANE, Badge) can be configured with one of these modes
 * to control whether verification is performed and how failures are handled.</p>
 *
 * @see VerificationPolicy
 */
public enum VerificationMode {

    /**
     * Do not perform this verification.
     *
     * <p>The verification step is completely skipped.</p>
     */
    DISABLED,

    /**
     * Perform verification but only log warnings on failure.
     *
     * <p>If verification fails, the connection proceeds but a warning is logged.
     * Use this when you want visibility into verification status without blocking
     * connections (e.g., during migration or when infrastructure may not support
     * the verification method).</p>
     */
    ADVISORY,

    /**
     * Perform verification and fail the connection on failure.
     *
     * <p>If verification fails, the connection is rejected with an exception.
     * Use this for strict security requirements where verification must succeed.</p>
     */
    REQUIRED
}