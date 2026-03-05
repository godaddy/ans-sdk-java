package com.godaddy.ans.sdk.agent.verification;

/**
 * Specifies how DNSSEC validation is performed for DANE/TLSA verification.
 *
 * <p>DANE security requires DNSSEC validation to ensure TLSA records haven't been tampered with.
 * This enum provides two approaches:</p>
 *
 * <h2>TRUST_RESOLVER (Default)</h2>
 * <p>Relies on an upstream DNSSEC-validating resolver (like Cloudflare, Google, or Quad9)
 * to perform validation. The resolver sets the AD (Authenticated Data) flag in responses
 * when DNSSEC validation succeeds. This is simple and fast but requires a DNSSEC-capable resolver.</p>
 *
 * <h2>VALIDATE_IN_CODE</h2>
 * <p>Performs DNSSEC validation locally using dnsjava's ValidatingResolver. This fetches
 * DNSKEY and RRSIG records and verifies the signature chain from the root trust anchor.
 * This works with any resolver (including non-DNSSEC ones) but requires more DNS queries
 * and cryptographic operations.</p>
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * // Use resolver-based validation (default, requires DNSSEC resolver)
 * DaneConfig config = DaneConfig.builder()
 *     .validationMode(DnssecValidationMode.TRUST_RESOLVER)
 *     .resolver(DnsResolverConfig.CLOUDFLARE)
 *     .build();
 *
 * // Use in-code validation (works with any resolver)
 * DaneConfig strictConfig = DaneConfig.builder()
 *     .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
 *     .resolver(DnsResolverConfig.SYSTEM)  // Can use system resolver
 *     .build();
 * }</pre>
 *
 * @see DaneConfig
 * @see DnsResolverConfig
 */
public enum DnssecValidationMode {

    /**
     * Trust the AD (Authenticated Data) flag from the upstream DNS resolver.
     *
     * <p>This mode requires a DNSSEC-validating resolver such as:</p>
     * <ul>
     *   <li>Cloudflare (1.1.1.1)</li>
     *   <li>Google (8.8.8.8)</li>
     *   <li>Quad9 (9.9.9.9)</li>
     * </ul>
     *
     * <p>If the resolver doesn't support DNSSEC validation, TLSA records will be rejected
     * as non-authenticated (AD flag not set).</p>
     *
     * <p><b>Pros:</b> Simple, fast, minimal DNS queries</p>
     * <p><b>Cons:</b> Requires DNSSEC-validating resolver</p>
     */
    TRUST_RESOLVER,

    /**
     * Perform DNSSEC validation locally using dnsjava's ValidatingResolver.
     *
     * <p>This mode validates the DNSSEC signature chain in code by:</p>
     * <ol>
     *   <li>Fetching DNSKEY records for each zone in the chain</li>
     *   <li>Fetching RRSIG records alongside the TLSA record</li>
     *   <li>Verifying each signature from root to the TLSA record</li>
     * </ol>
     *
     * <p>This works with any resolver, including non-DNSSEC ones like the system resolver,
     * because validation is performed locally rather than by the resolver.</p>
     *
     * <p><b>Pros:</b> Works with any resolver, full control over validation</p>
     * <p><b>Cons:</b> More DNS queries (DNSKEY, RRSIG), requires trust anchors</p>
     */
    VALIDATE_IN_CODE;

    /**
     * Returns whether this mode performs validation locally.
     *
     * @return true if validation is done in code, false if trusting resolver
     */
    public boolean isInCodeValidation() {
        return this == VALIDATE_IN_CODE;
    }

    /**
     * Returns whether this mode requires a DNSSEC-validating resolver.
     *
     * @return true if resolver must support DNSSEC, false otherwise
     */
    public boolean requiresDnssecResolver() {
        return this == TRUST_RESOLVER;
    }
}
