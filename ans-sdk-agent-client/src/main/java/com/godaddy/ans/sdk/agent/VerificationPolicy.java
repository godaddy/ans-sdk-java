package com.godaddy.ans.sdk.agent;

import java.util.Objects;

/**
 * Configures which verification methods to use when connecting to an agent.
 *
 * <p>Each verification type can be independently configured:</p>
 * <ul>
 *   <li><b>DANE</b>: DNS-based Authentication of Named Entities (TLSA records)</li>
 *   <li><b>Badge</b>: ANS transparency log verification (proof of registration)</li>
 *   <li><b>SCITT</b>: Cryptographic proof via HTTP headers (receipts and status tokens)</li>
 * </ul>
 *
 * <h2>Using Presets</h2>
 * <p>For common scenarios, use the predefined policies:</p>
 * <pre>{@code
 * // Badge verification only (recommended for most cases)
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
 *     .build();
 *
 * // SCITT verification with badge fallback
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.SCITT_ENHANCED)
 *     .build();
 *
 * </pre>
 *
 * <h2>Custom Configuration</h2>
 * <p>For advanced scenarios, use the builder:</p>
 * <pre>{@code
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.custom()
 *         .dane(VerificationMode.ADVISORY)    // Try DANE, log on failure
 *         .badge(VerificationMode.REQUIRED)   // Must verify badge
 *         .scitt(VerificationMode.ADVISORY)   // Try SCITT, fall back to badge
 *         .build())
 *     .build();
 * }</pre>
 *
 * @param daneMode the DANE verification mode
 * @param badgeMode the Badge verification mode
 * @param scittMode the SCITT verification mode
 * @see VerificationMode
 * @see ConnectOptions.Builder#verificationPolicy(VerificationPolicy)
 */
public record VerificationPolicy(
    VerificationMode daneMode,
    VerificationMode badgeMode,
    VerificationMode scittMode
) {
    // ==================== Predefined Policies ====================

    /**
     * Standard PKI trust only - no additional verification.
     *
     * <p>Uses the JVM's default trust store to validate certificates against
     * well-known Certificate Authorities. This is the minimum security level.</p>
     */
    public static final VerificationPolicy PKI_ONLY = new VerificationPolicy(
        VerificationMode.DISABLED,
        VerificationMode.DISABLED,
        VerificationMode.DISABLED
    );

    /**
     * Badge verification required via ANS transparency log.
     *
     * <p>Verifies that the server is a registered ANS agent by checking the
     * transparency log. This is the recommended default for most use cases
     * as it provides strong identity assurance without requiring DNSSEC.</p>
     */
    public static final VerificationPolicy BADGE_REQUIRED = new VerificationPolicy(
        VerificationMode.DISABLED,
        VerificationMode.REQUIRED,
        VerificationMode.DISABLED
    );

    /**
     * DANE verification in advisory mode (logs warnings on failure).
     *
     * <p>Attempts DANE/TLSA verification but allows connections even if
     * verification fails. Useful for monitoring DANE deployment status.</p>
     */
    public static final VerificationPolicy DANE_ADVISORY = new VerificationPolicy(
        VerificationMode.ADVISORY,
        VerificationMode.DISABLED,
        VerificationMode.DISABLED
    );

    /**
     * DANE verification required.
     *
     * <p>Requires DNSSEC-secured TLSA records to match the server certificate.
     * Use this when connecting to agents with DNSSEC-enabled infrastructure.</p>
     */
    public static final VerificationPolicy DANE_REQUIRED = new VerificationPolicy(
        VerificationMode.REQUIRED,
        VerificationMode.DISABLED,
        VerificationMode.DISABLED
    );

    /**
     * Both DANE and Badge verification required.
     *
     * <p>Combines DNS-based verification with transparency log verification
     * for maximum assurance. Requires both DNSSEC infrastructure and ANS
     * registration.</p>
     */
    public static final VerificationPolicy DANE_AND_BADGE = new VerificationPolicy(
        VerificationMode.REQUIRED,
        VerificationMode.REQUIRED,
        VerificationMode.DISABLED
    );

    /**
     * SCITT verification with badge fallback.
     *
     * <p>Uses SCITT artifacts (receipts and status tokens) delivered via HTTP headers
     * for verification. Falls back to badge verification if SCITT headers are not
     * present. This is the recommended migration path from badge-based verification.</p>
     */
    public static final VerificationPolicy SCITT_ENHANCED = new VerificationPolicy(
        VerificationMode.DISABLED,
        VerificationMode.ADVISORY,
        VerificationMode.REQUIRED
    );

    /**
     * SCITT verification required, no fallback.
     *
     * <p><b>Recommended for production.</b> Requires SCITT artifacts for verification
     * with no badge fallback. This prevents downgrade attacks where an attacker
     * strips SCITT headers to force badge-based verification.</p>
     */
    public static final VerificationPolicy SCITT_REQUIRED = new VerificationPolicy(
        VerificationMode.DISABLED,
        VerificationMode.DISABLED,
        VerificationMode.REQUIRED
    );

    // ==================== Compact Constructor ====================

    /**
     * Validates that all modes are non-null.
     */
    public VerificationPolicy {
        Objects.requireNonNull(daneMode, "daneMode cannot be null");
        Objects.requireNonNull(badgeMode, "badgeMode cannot be null");
        Objects.requireNonNull(scittMode, "scittMode cannot be null");
    }

    // ==================== Factory Methods ====================

    /**
     * Creates a builder for custom verification policies.
     *
     * @return a new builder with all verifications disabled by default
     */
    public static Builder custom() {
        return new Builder();
    }

    // ==================== Utility Methods ====================

    /**
     * Checks if any verification is enabled.
     *
     * @return true if at least one verification mode is not DISABLED
     */
    public boolean hasAnyVerification() {
        return daneMode != VerificationMode.DISABLED
            || badgeMode != VerificationMode.DISABLED
            || scittMode != VerificationMode.DISABLED;
    }

    /**
     * Checks if SCITT verification is enabled.
     *
     * @return true if SCITT mode is not DISABLED
     */
    public boolean hasScittVerification() {
        return scittMode != VerificationMode.DISABLED;
    }

    @Override
    public String toString() {
        return "VerificationPolicy{dane=" + daneMode +
            ", badge=" + badgeMode +
            ", scitt=" + scittMode + "}";
    }

    // ==================== Builder ====================

    /**
     * Builder for creating custom verification policies.
     *
     * <p>All verification modes default to {@link VerificationMode#DISABLED}.</p>
     */
    public static final class Builder {
        private VerificationMode daneMode = VerificationMode.DISABLED;
        private VerificationMode badgeMode = VerificationMode.DISABLED;
        private VerificationMode scittMode = VerificationMode.DISABLED;

        private Builder() {
        }

        /**
         * Sets the DANE verification mode.
         *
         * <p>DANE (DNS-based Authentication of Named Entities) uses DNSSEC-secured
         * TLSA records to verify the server certificate matches what's published
         * in DNS.</p>
         *
         * @param mode the verification mode
         * @return this builder
         */
        public Builder dane(VerificationMode mode) {
            this.daneMode = Objects.requireNonNull(mode, "mode cannot be null");
            return this;
        }

        /**
         * Sets the Badge verification mode.
         *
         * <p>Badge verification checks the ANS transparency log to confirm
         * the agent is registered and the certificate fingerprint matches the
         * registration (the "badge" or proof of registration).</p>
         *
         * @param mode the verification mode
         * @return this builder
         */
        public Builder badge(VerificationMode mode) {
            this.badgeMode = Objects.requireNonNull(mode, "mode cannot be null");
            return this;
        }

        /**
         * Sets the SCITT verification mode.
         *
         * <p>SCITT (Supply Chain Integrity, Transparency, and Trust) verification
         * uses cryptographic receipts and status tokens delivered via HTTP headers.
         * This eliminates the need for live transparency log queries.</p>
         *
         * @param mode the verification mode
         * @return this builder
         */
        public Builder scitt(VerificationMode mode) {
            this.scittMode = Objects.requireNonNull(mode, "mode cannot be null");
            return this;
        }

        /**
         * Builds the verification policy.
         *
         * @return the configured policy
         */
        public VerificationPolicy build() {
            return new VerificationPolicy(daneMode, badgeMode, scittMode);
        }
    }
}
