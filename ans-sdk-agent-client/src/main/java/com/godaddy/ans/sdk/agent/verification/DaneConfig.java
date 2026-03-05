package com.godaddy.ans.sdk.agent.verification;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for DANE/TLSA verification.
 *
 * <p>This record holds all configuration options for DANE verification,
 * including the verification policy, DNS resolver selection, DNSSEC validation mode,
 * and cache settings.</p>
 *
 * <h2>Configuration Options</h2>
 * <ul>
 *   <li><b>policy</b>: When to perform DANE verification (DISABLED, VALIDATE_IF_PRESENT, REQUIRED)</li>
 *   <li><b>resolver</b>: Which DNS resolver to use (SYSTEM, CLOUDFLARE, GOOGLE, QUAD9)</li>
 *   <li><b>validationMode</b>: How to validate DNSSEC (TRUST_RESOLVER, VALIDATE_IN_CODE)</li>
 *   <li><b>cacheTtl</b>: How long to cache TLSA verification results</li>
 * </ul>
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * // Default configuration (opportunistic DANE with Cloudflare DNS, trust resolver)
 * DaneConfig config = DaneConfig.defaults();
 *
 * // Custom configuration with in-code DNSSEC validation
 * DaneConfig strictConfig = DaneConfig.builder()
 *     .policy(DanePolicy.REQUIRED)
 *     .resolver(DnsResolverConfig.SYSTEM)  // Can use system resolver with in-code validation
 *     .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
 *     .cacheTtl(Duration.ofMinutes(30))
 *     .build();
 *
 * // Create verifier with config
 * DaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(strictConfig);
 * }</pre>
 *
 * @param policy the DANE verification policy
 * @param resolver the DNS resolver configuration
 * @param validationMode how DNSSEC validation is performed
 * @param cacheTtl how long to cache TLSA results (use Duration.ZERO to disable caching)
 *
 * @see DanePolicy
 * @see DnsResolverConfig
 * @see DnssecValidationMode
 * @see DefaultDaneTlsaVerifier
 */
public record DaneConfig(
    DanePolicy policy,
    DnsResolverConfig resolver,
    DnssecValidationMode validationMode,
    Duration cacheTtl
) {

    /**
     * Default cache TTL (1 hour).
     */
    public static final Duration DEFAULT_CACHE_TTL = Duration.ofHours(1);

    /**
     * Compact constructor with validation.
     */
    public DaneConfig {
        Objects.requireNonNull(policy, "policy cannot be null");
        Objects.requireNonNull(resolver, "resolver cannot be null");
        Objects.requireNonNull(validationMode, "validationMode cannot be null");
        Objects.requireNonNull(cacheTtl, "cacheTtl cannot be null");
        if (cacheTtl.isNegative()) {
            throw new IllegalArgumentException("cacheTtl cannot be negative");
        }
    }

    /**
     * Returns the default configuration.
     *
     * <p>Defaults:</p>
     * <ul>
     *   <li>Policy: VALIDATE_IF_PRESENT (opportunistic DANE)</li>
     *   <li>Resolver: CLOUDFLARE (1.1.1.1 - DNSSEC-validating)</li>
     *   <li>Validation Mode: TRUST_RESOLVER (trust AD flag from resolver)</li>
     *   <li>Cache TTL: 1 hour</li>
     * </ul>
     *
     * @return the default configuration
     */
    public static DaneConfig defaults() {
        return new DaneConfig(
            DanePolicy.VALIDATE_IF_PRESENT,
            DnsResolverConfig.CLOUDFLARE,
            DnssecValidationMode.TRUST_RESOLVER,
            DEFAULT_CACHE_TTL
        );
    }

    /**
     * Returns a configuration with DANE disabled.
     *
     * <p>Use this when DANE verification is not needed or handled elsewhere.</p>
     *
     * @return a disabled configuration
     */
    public static DaneConfig disabled() {
        return new DaneConfig(
            DanePolicy.DISABLED,
            DnsResolverConfig.SYSTEM,
            DnssecValidationMode.TRUST_RESOLVER,
            Duration.ZERO
        );
    }

    /**
     * Creates a new builder for DaneConfig.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link DaneConfig}.
     */
    public static final class Builder {
        private DanePolicy policy = DanePolicy.VALIDATE_IF_PRESENT;
        private DnsResolverConfig resolver = DnsResolverConfig.CLOUDFLARE;
        private DnssecValidationMode validationMode = DnssecValidationMode.TRUST_RESOLVER;
        private Duration cacheTtl = DEFAULT_CACHE_TTL;

        private Builder() {}

        /**
         * Sets the DANE verification policy.
         *
         * @param policy the policy
         * @return this builder
         */
        public Builder policy(DanePolicy policy) {
            this.policy = Objects.requireNonNull(policy, "policy cannot be null");
            return this;
        }

        /**
         * Sets the DNS resolver configuration.
         *
         * @param resolver the resolver config
         * @return this builder
         */
        public Builder resolver(DnsResolverConfig resolver) {
            this.resolver = Objects.requireNonNull(resolver, "resolver cannot be null");
            return this;
        }

        /**
         * Sets the DNSSEC validation mode.
         *
         * <p>Use {@link DnssecValidationMode#TRUST_RESOLVER} (default) to trust the AD flag
         * from a DNSSEC-validating resolver like Cloudflare or Google.</p>
         *
         * <p>Use {@link DnssecValidationMode#VALIDATE_IN_CODE} to perform DNSSEC validation
         * locally, which works with any resolver including the system resolver.</p>
         *
         * @param validationMode the validation mode
         * @return this builder
         */
        public Builder validationMode(DnssecValidationMode validationMode) {
            this.validationMode = Objects.requireNonNull(validationMode, "validationMode cannot be null");
            return this;
        }

        /**
         * Sets the cache TTL for TLSA results.
         *
         * <p>Use {@link Duration#ZERO} to disable caching.</p>
         *
         * @param cacheTtl the cache TTL
         * @return this builder
         */
        public Builder cacheTtl(Duration cacheTtl) {
            this.cacheTtl = Objects.requireNonNull(cacheTtl, "cacheTtl cannot be null");
            return this;
        }

        /**
         * Builds the configuration.
         *
         * @return the built configuration
         */
        public DaneConfig build() {
            return new DaneConfig(policy, resolver, validationMode, cacheTtl);
        }
    }
}
