package com.godaddy.ans.sdk.agent.verification;

/**
 * Pre-configured DNS resolver options for DANE/DNSSEC validation.
 *
 * <p>DANE security depends on DNSSEC validation. Most system resolvers don't support
 * DNSSEC, so this enum provides easy access to well-known public DNSSEC-validating
 * resolvers.</p>
 *
 * <h2>DNSSEC Requirement</h2>
 * <p>For DANE to be secure, TLSA records must be DNSSEC-validated. This means:</p>
 * <ul>
 *   <li>The domain must have DNSSEC enabled (DNSKEY, RRSIG records)</li>
 *   <li>The resolver must validate the DNSSEC signature chain</li>
 *   <li>The resolver must set the AD (Authenticated Data) flag on validated responses</li>
 * </ul>
 *
 * <h2>Resolver Options</h2>
 * <table>
 *   <tr><th>Config</th><th>Primary IP</th><th>Provider</th></tr>
 *   <tr><td>CLOUDFLARE</td><td>1.1.1.1</td><td>Cloudflare DNS</td></tr>
 *   <tr><td>GOOGLE</td><td>8.8.8.8</td><td>Google Public DNS</td></tr>
 *   <tr><td>QUAD9</td><td>9.9.9.9</td><td>Quad9 (includes malware blocking)</td></tr>
 *   <tr><td>SYSTEM</td><td>varies</td><td>System default (may not support DNSSEC)</td></tr>
 * </table>
 *
 * <h2>Example Usage</h2>
 * <pre>{@code
 * // Use Cloudflare DNS (default)
 * DaneConfig config = DaneConfig.builder()
 *     .resolver(DnsResolverConfig.CLOUDFLARE)
 *     .build();
 *
 * // Use Google DNS
 * DaneConfig googleConfig = DaneConfig.builder()
 *     .resolver(DnsResolverConfig.GOOGLE)
 *     .build();
 * }</pre>
 *
 * @see DaneConfig
 * @see DanePolicy
 */
public enum DnsResolverConfig {

    /**
     * Use the system's default DNS resolver.
     *
     * <p><b>Warning:</b> Most system resolvers do not perform DNSSEC validation.
     * If your system resolver doesn't validate DNSSEC, TLSA records will be
     * rejected as non-authenticated.</p>
     *
     * <p>Use this only if you have a local DNSSEC-validating resolver configured.</p>
     */
    SYSTEM(null, null),

    /**
     * Cloudflare DNS (1.1.1.1, 1.0.0.1).
     *
     * <p>Cloudflare's public DNS service with DNSSEC validation.
     * Known for low latency and privacy focus.</p>
     *
     * @see <a href="https://1.1.1.1/">Cloudflare DNS</a>
     */
    CLOUDFLARE("1.1.1.1", "1.0.0.1"),

    /**
     * Google Public DNS (8.8.8.8, 8.8.4.4).
     *
     * <p>Google's public DNS service with DNSSEC validation.
     * Widely used and highly reliable.</p>
     *
     * @see <a href="https://developers.google.com/speed/public-dns">Google Public DNS</a>
     */
    GOOGLE("8.8.8.8", "8.8.4.4"),

    /**
     * Quad9 DNS (9.9.9.9, 149.112.112.112).
     *
     * <p>Quad9's public DNS service with DNSSEC validation and built-in
     * malware/phishing blocking. Operated by the Quad9 Foundation.</p>
     *
     * @see <a href="https://quad9.net/">Quad9</a>
     */
    QUAD9("9.9.9.9", "149.112.112.112");

    private final String primaryAddress;
    private final String secondaryAddress;

    DnsResolverConfig(String primaryAddress, String secondaryAddress) {
        this.primaryAddress = primaryAddress;
        this.secondaryAddress = secondaryAddress;
    }

    /**
     * Returns the primary DNS server address.
     *
     * @return the primary IP address, or null for SYSTEM
     */
    public String getPrimaryAddress() {
        return primaryAddress;
    }

    /**
     * Returns the secondary (fallback) DNS server address.
     *
     * @return the secondary IP address, or null for SYSTEM
     */
    public String getSecondaryAddress() {
        return secondaryAddress;
    }

    /**
     * Returns whether this config uses the system resolver.
     *
     * @return true if this is the SYSTEM config
     */
    public boolean isSystemResolver() {
        return this == SYSTEM;
    }
}