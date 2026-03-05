package com.godaddy.ans.sdk.agent;

import java.util.Objects;

/**
 * Configures which verification methods to use when connecting to an agent.
 *
 * <p>Each verification type can be independently configured:</p>
 * <ul>
 *   <li><b>DANE</b>: DNS-based Authentication of Named Entities (TLSA records)</li>
 *   <li><b>Badge</b>: ANS transparency log verification (proof of registration)</li>
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
 * // Full verification (all methods required)
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.FULL)
 *     .build();
 * }</pre>
 *
 * <h2>Custom Configuration</h2>
 * <p>For advanced scenarios, use the builder:</p>
 * <pre>{@code
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.custom()
 *         .dane(VerificationMode.ADVISORY)    // Try DANE, log on failure
 *         .badge(VerificationMode.REQUIRED)   // Must verify badge
 *         .build())
 *     .build();
 * }</pre>
 *
 * @param daneMode the DANE verification mode
 * @param badgeMode the Badge verification mode
 * @see VerificationMode
 * @see ConnectOptions.Builder#verificationPolicy(VerificationPolicy)
 */
public record VerificationPolicy(
    VerificationMode daneMode,
    VerificationMode badgeMode
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
        VerificationMode.REQUIRED
    );

    /**
     * DANE verification in advisory mode (logs warnings on failure).
     *
     * <p>Attempts DANE/TLSA verification but allows connections even if
     * verification fails. Useful for monitoring DANE deployment status.</p>
     */
    public static final VerificationPolicy DANE_ADVISORY = new VerificationPolicy(
        VerificationMode.ADVISORY,
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
        VerificationMode.REQUIRED
    );

    /**
     * All verification methods required.
     *
     * <p>Maximum security: requires both DANE and Badge verification.</p>
     */
    public static final VerificationPolicy FULL = new VerificationPolicy(
        VerificationMode.REQUIRED,
        VerificationMode.REQUIRED
    );

    // ==================== Compact Constructor ====================

    /**
     * Validates that all modes are non-null.
     */
    public VerificationPolicy {
        Objects.requireNonNull(daneMode, "daneMode cannot be null");
        Objects.requireNonNull(badgeMode, "badgeMode cannot be null");
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
            || badgeMode != VerificationMode.DISABLED;
    }

    @Override
    public String toString() {
        return "VerificationPolicy{dane=" + daneMode +
            ", badge=" + badgeMode + "}";
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
         * Builds the verification policy.
         *
         * @return the configured policy
         */
        public VerificationPolicy build() {
            return new VerificationPolicy(daneMode, badgeMode);
        }
    }
}
