package com.godaddy.ans.sdk.transparency.verification;

/**
 * Status codes for agent verification results.
 */
public enum VerificationStatus {

    /**
     * The agent is verified and has an ACTIVE registration.
     */
    VERIFIED,

    /**
     * The agent is verified but has a DEPRECATED registration.
     * This is acceptable during version rotation grace periods.
     */
    DEPRECATED_OK,

    /**
     * The host does not have an ra-badge DNS record, indicating
     * it is not an ANS-registered agent.
     */
    NOT_ANS_AGENT,

    /**
     * The registration exists but has an invalid status
     * (e.g., REVOKED, EXPIRED).
     */
    REGISTRATION_INVALID,

    /**
     * The certificate fingerprint does not match the one
     * recorded in the transparency log.
     */
    FINGERPRINT_MISMATCH,

    /**
     * The ANS name in the certificate does not match the
     * registration's ANS name.
     */
    ANS_NAME_MISMATCH,

    /**
     * The certificate CN does not match the agent.host
     * from the transparency log registration.
     */
    HOSTNAME_MISMATCH,

    /**
     * Failed to look up the registration (network error, DNS error, etc.).
     */
    LOOKUP_FAILED
}