package com.godaddy.ans.sdk.agent.verification;

/**
 * DANE verification policy controlling when TLSA records are checked.
 *
 * <p>DANE (DNS-Based Authentication of Named Entities) binds TLS certificates
 * to DNS records via TLSA records. This enum controls the verification behavior.</p>
 *
 * <h2>Policy Options</h2>
 * <ul>
 *   <li><b>DISABLED</b>: Never check TLSA records. Use when DANE is not needed.</li>
 *   <li><b>VALIDATE_IF_PRESENT</b>: Check TLSA if it exists; skip silently if not.
 *       This adds security opportunistically without breaking domains without DANE.</li>
 *   <li><b>REQUIRED</b>: TLSA record must exist and validate. Connections are rejected
 *       if TLSA is missing or doesn't match.</li>
 * </ul>
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * // Opportunistic DANE (default)
 * DaneConfig config = DaneConfig.builder()
 *     .policy(DanePolicy.VALIDATE_IF_PRESENT)
 *     .build();
 *
 * // Strict DANE requirement
 * DaneConfig strictConfig = DaneConfig.builder()
 *     .policy(DanePolicy.REQUIRED)
 *     .build();
 * }</pre>
 *
 * @see DaneConfig
 * @see DaneTlsaVerifier
 */
public enum DanePolicy {

    /**
     * Never check TLSA records.
     *
     * <p>DANE verification is completely skipped. This is useful when:
     * <ul>
     *   <li>Performance is critical and DANE overhead is unacceptable</li>
     *   <li>The environment doesn't support DNSSEC</li>
     *   <li>DANE is handled at a different layer (e.g., load balancer)</li>
     * </ul>
     */
    DISABLED,

    /**
     * Validate TLSA records if present; skip if not found.
     *
     * <p>This is the recommended default for most deployments. It provides:
     * <ul>
     *   <li>Enhanced security for domains with DANE configured</li>
     *   <li>No breakage for domains without DANE</li>
     *   <li>Graceful degradation if DNS is unavailable</li>
     * </ul>
     */
    VALIDATE_IF_PRESENT,

    /**
     * Require TLSA records to exist and validate.
     *
     * <p>This is the strictest policy. Connections are rejected if:
     * <ul>
     *   <li>No TLSA record exists for the host</li>
     *   <li>TLSA record doesn't match the server certificate</li>
     *   <li>DNSSEC validation fails</li>
     * </ul>
     *
     * <p>Use this when DANE is mandatory for compliance or security requirements.</p>
     */
    REQUIRED;

    /**
     * Returns whether DANE verification should be performed.
     *
     * @return true if DANE verification should be attempted
     */
    public boolean shouldVerify() {
        return this != DISABLED;
    }

    /**
     * Returns whether TLSA records are required to exist.
     *
     * @return true if missing TLSA records should cause rejection
     */
    public boolean isRequired() {
        return this == REQUIRED;
    }
}