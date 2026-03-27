package com.godaddy.ans.sdk.transparency.scitt;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Registry of trusted SCITT domains for the ANS transparency infrastructure.
 *
 * <p>Trusted domains can be configured via the system property
 * {@value #TRUSTED_DOMAINS_PROPERTY}. If not set, defaults to the production
 * ANS transparency log domains.</p>
 *
 * <p><b>Security note:</b> Only domains in this registry will be trusted for
 * fetching SCITT root keys. This prevents root key substitution attacks.</p>
 *
 * <p><b>Immutability:</b> The trusted domain set is captured once at class
 * initialization and cannot be changed afterward. This prevents runtime
 * modification attacks via system property manipulation.</p>
 *
 * <h2>Configuration</h2>
 * <pre>{@code
 * # Use default production domains (no property set)
 *
 * # Or specify custom domains (comma-separated) - must be set BEFORE first use
 * -Dans.transparency.trusted.domains=transparency.ans.godaddy.com,localhost
 * }</pre>
 */
public final class TrustedDomainRegistry {

    /**
     * System property to specify trusted domains (comma-separated).
     * If not set, defaults to production ANS transparency log domains.
     * <p><b>Note:</b> This property is read only once at class initialization.
     * Changes after that point have no effect.</p>
     */
    public static final String TRUSTED_DOMAINS_PROPERTY = "ans.transparency.trusted.domains";

    /**
     * Default trusted SCITT domains used when no system property is set.
     */
    public static final Set<String> DEFAULT_TRUSTED_DOMAINS = Set.of(
        "transparency.ans.godaddy.com",
        "transparency.ans.ote-godaddy.com"
    );

    /**
     * Immutable set of trusted domains, captured once at class initialization.
     * This ensures the trusted domain set cannot be modified at runtime via
     * system property manipulation - a security requirement for trust anchors.
     */
    private static final Set<String> TRUSTED_DOMAINS;

    static {
        String property = System.getProperty(TRUSTED_DOMAINS_PROPERTY);
        if (property == null || property.isBlank()) {
            TRUSTED_DOMAINS = DEFAULT_TRUSTED_DOMAINS;
        } else {
            TRUSTED_DOMAINS = Arrays.stream(property.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toLowerCase)
                .collect(Collectors.toUnmodifiableSet());
        }
    }

    private TrustedDomainRegistry() {
        // Utility class
    }

    /**
     * Checks if a domain is trusted.
     *
     * @param domain the domain to check
     * @return true if the domain is trusted
     */
    public static boolean isTrustedDomain(String domain) {
        if (domain == null) {
            return false;
        }
        return TRUSTED_DOMAINS.contains(domain.toLowerCase());
    }

    /**
     * Returns the set of trusted domains.
     *
     * <p>The returned set is immutable and was captured at class initialization.
     * Subsequent changes to the system property have no effect.</p>
     *
     * @return trusted domains (immutable)
     */
    public static Set<String> getTrustedDomains() {
        return TRUSTED_DOMAINS;
    }
}
