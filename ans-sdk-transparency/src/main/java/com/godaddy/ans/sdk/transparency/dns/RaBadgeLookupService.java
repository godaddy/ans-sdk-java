package com.godaddy.ans.sdk.transparency.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Service for looking up badge TXT records from DNS.
 *
 * <p>This service supports both {@code _ans-badge} and legacy {@code _ra-badge} records,
 * with {@code _ans-badge} taking priority when both exist. The badge TXT record points
 * to the transparency log URL for an agent.</p>
 *
 * <p>During version rotation, multiple badge records may exist.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * RaBadgeLookupService lookup = new RaBadgeLookupService();
 *
 * // Check if host has badge
 * if (lookup.hasBadgeRecord("agent.example.com")) {
 *     List<RaBadgeRecord> badges = lookup.lookupBadges("agent.example.com");
 *     for (RaBadgeRecord badge : badges) {
 *         System.out.println("Agent ID: " + badge.agentId());
 *         System.out.println("URL: " + badge.url());
 *     }
 * }
 * }</pre>
 */
public class RaBadgeLookupService {

    private static final Logger LOGGER = LoggerFactory.getLogger(RaBadgeLookupService.class);

    private static final String ANS_BADGE_PREFIX = "_ans-badge.";
    private static final String RA_BADGE_PREFIX = "_ra-badge.";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    private final String dnsServer;
    private final Duration timeout;

    /**
     * Creates a new RaBadgeLookupService using the system default DNS resolver.
     */
    public RaBadgeLookupService() {
        this(null, DEFAULT_TIMEOUT);
    }

    /**
     * Creates a new RaBadgeLookupService with custom settings.
     *
     * @param dnsServer optional DNS server to use (null for system default)
     * @param timeout DNS query timeout
     */
    public RaBadgeLookupService(String dnsServer, Duration timeout) {
        this.dnsServer = dnsServer;
        this.timeout = timeout != null ? timeout : DEFAULT_TIMEOUT;
    }

    /**
     * Looks up all badge TXT records for a hostname.
     *
     * <p>This method checks BOTH {@code _ans-badge} and {@code _ra-badge} records
     * and combines the results. This is important during version rotation where
     * old versions may use {@code _ra-badge} while new versions use {@code _ans-badge}.</p>
     *
     * <p>During version rotation, multiple records may exist across both prefixes.
     * All valid records are returned.</p>
     *
     * @param hostname the agent's hostname (e.g., "agent.example.com")
     * @return list of badge records, empty if none found
     */
    public List<RaBadgeRecord> lookupBadges(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            return Collections.emptyList();
        }

        String normalizedHostname = normalizeHostname(hostname);
        List<RaBadgeRecord> allBadges = new ArrayList<>();

        // Check _ans-badge records
        String ansBadgeName = ANS_BADGE_PREFIX + normalizedHostname;
        List<RaBadgeRecord> ansBadges = lookupBadgesForPrefix(ansBadgeName, "_ans-badge");
        if (!ansBadges.isEmpty()) {
            LOGGER.debug("Found {} _ans-badge records for {}", ansBadges.size(), hostname);
            allBadges.addAll(ansBadges);
        }

        // Also check _ra-badge records (for version rotation compatibility)
        String raBadgeName = RA_BADGE_PREFIX + normalizedHostname;
        List<RaBadgeRecord> raBadges = lookupBadgesForPrefix(raBadgeName, "_ra-badge");
        if (!raBadges.isEmpty()) {
            LOGGER.debug("Found {} _ra-badge records for {}", raBadges.size(), hostname);
            allBadges.addAll(raBadges);
        }

        if (allBadges.isEmpty()) {
            LOGGER.debug("No badge TXT records found for {}", hostname);
        }

        return allBadges;
    }

    /**
     * Looks up badge TXT records for a specific DNS name.
     *
     * @param dnsName the full DNS name to query (e.g., "_ans-badge.agent.example.com")
     * @param prefixType the prefix type for logging (e.g., "_ans-badge")
     * @return list of badge records, empty if none found
     */
    private List<RaBadgeRecord> lookupBadgesForPrefix(String dnsName, String prefixType) {
        LOGGER.debug("Looking up TXT record: {}", dnsName);

        try {
            List<String> txtValues = lookupTxtRecords(dnsName);

            if (txtValues.isEmpty()) {
                return Collections.emptyList();
            }

            List<RaBadgeRecord> badges = new ArrayList<>();
            for (String txtValue : txtValues) {
                RaBadgeRecord badge = RaBadgeRecord.parse(txtValue);
                if (badge != null && badge.isSupportedBadgeFormat()) {
                    badges.add(badge);
                    LOGGER.debug("Found {} badge: {}", prefixType, badge);
                }
            }

            return badges;

        } catch (Exception e) {
            LOGGER.warn("Failed to lookup {} for {}: {}", prefixType, dnsName, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Performs the actual DNS TXT record lookup.
     *
     * <p>This method is protected to allow subclasses to override it for testing.</p>
     *
     * @param dnsName the DNS name to query
     * @return list of TXT record values, empty if none found
     */
    protected List<String> lookupTxtRecords(String dnsName) {
        try {
            Lookup lookup = new Lookup(dnsName, Type.TXT);
            configureResolver(lookup);

            Record[] records = lookup.run();

            if (records == null || records.length == 0) {
                return Collections.emptyList();
            }

            List<String> results = new ArrayList<>();
            for (Record record : records) {
                if (record instanceof TXTRecord txtRecord) {
                    String txtValue = parseTxtRecord(txtRecord);
                    if (txtValue != null) {
                        results.add(txtValue);
                    }
                }
            }

            return results;

        } catch (Exception e) {
            LOGGER.debug("DNS lookup failed for {}: {}", dnsName, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Checks if a hostname has any badge TXT records.
     *
     * <p>Checks for both {@code _ans-badge} and {@code _ra-badge} records.</p>
     *
     * @param hostname the agent's hostname
     * @return true if at least one valid badge record exists
     */
    public boolean hasBadgeRecord(String hostname) {
        return !lookupBadges(hostname).isEmpty();
    }

    /**
     * Looks up a single badge record for a hostname.
     *
     * <p>If multiple records exist, returns the first one. Uses {@code _ans-badge}
     * priority over {@code _ra-badge}. Use {@link #lookupBadges(String)} to get
     * all records during version rotation.</p>
     *
     * @param hostname the agent's hostname
     * @return the badge record, or null if not found
     */
    public RaBadgeRecord lookupBadge(String hostname) {
        List<RaBadgeRecord> badges = lookupBadges(hostname);
        return badges.isEmpty() ? null : badges.get(0);
    }

    /**
     * Parses a TXT record into a string value.
     */
    private String parseTxtRecord(TXTRecord txtRecord) {
        // TXT records can have multiple strings, concatenate them
        @SuppressWarnings("unchecked")
        List<String> strings = txtRecord.getStrings();
        if (strings == null || strings.isEmpty()) {
            return null;
        }

        // Join all strings (TXT records can be split)
        StringBuilder sb = new StringBuilder();
        for (String s : strings) {
            sb.append(s);
        }

        return sb.toString();
    }

    /**
     * Configures the DNS resolver for the lookup.
     */
    private void configureResolver(Lookup lookup) {
        try {
            SimpleResolver resolver;
            if (dnsServer != null && !dnsServer.isBlank()) {
                resolver = new SimpleResolver(dnsServer);
                LOGGER.debug("Using configured DNS server: {}", dnsServer);
            } else {
                resolver = new SimpleResolver();
                LOGGER.debug("Using system default DNS resolver");
            }
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
        } catch (Exception e) {
            LOGGER.debug("Failed to configure resolver: {}, using default", e.getMessage());
        }
    }

    /**
     * Normalizes the hostname for DNS lookup.
     */
    private String normalizeHostname(String hostname) {
        // Remove trailing dot if present
        if (hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }
        return hostname;
    }
}