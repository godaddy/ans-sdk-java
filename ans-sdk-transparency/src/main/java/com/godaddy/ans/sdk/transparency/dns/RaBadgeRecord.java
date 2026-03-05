package com.godaddy.ans.sdk.transparency.dns;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a parsed _ra-badge TXT record.
 *
 * <p>The _ra-badge TXT record format is:</p>
 * <pre>
 * v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/{uuid}
 * </pre>
 *
 * <p>Where:</p>
 * <ul>
 *   <li>{@code v=ra-badge1} - the badge format version</li>
 *   <li>{@code version=1.0.0} - the agent's semantic version (optional for backwards compatibility)</li>
 *   <li>{@code url=...} - the transparency log URL for this agent</li>
 * </ul>
 *
 * @param badgeVersion the badge format version (e.g., "ra-badge1")
 * @param agentVersion the agent's semantic version (e.g., "1.0.0"), may be null
 * @param url the full transparency log URL
 * @param agentId the extracted agent ID from the URL
 */
public record RaBadgeRecord(
    String badgeVersion,
    String agentVersion,
    String url,
    String agentId
) {
    // Pattern to parse ra-badge TXT record
    // Matches: v=ra-badge1; version=1.0.0; url=https://... (version is optional)
    private static final Pattern BADGE_PATTERN = Pattern.compile(
        "v=([^;\\s]+)\\s*;\\s*(?:version=([^;\\s]+)\\s*;\\s*)?url=([^\\s]+)",
        Pattern.CASE_INSENSITIVE
    );

    // Pattern to extract agent ID from URL path
    private static final Pattern AGENT_ID_PATTERN = Pattern.compile(
        "/v1/agents/([a-f0-9-]+)/?$",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * Parses a TXT record value into an RaBadgeRecord.
     *
     * @param txtValue the raw TXT record value
     * @return the parsed record, or null if the format is invalid
     */
    public static RaBadgeRecord parse(String txtValue) {
        if (txtValue == null || txtValue.isBlank()) {
            return null;
        }

        Matcher matcher = BADGE_PATTERN.matcher(txtValue.trim());
        if (!matcher.find()) {
            return null;
        }

        String badgeVersion = matcher.group(1);
        String agentVersion = matcher.group(2); // May be null if not present
        String url = matcher.group(3);

        // Extract agent ID from URL
        String agentId = extractAgentId(url);

        return new RaBadgeRecord(badgeVersion, agentVersion, url, agentId);
    }

    /**
     * Extracts the agent ID from a transparency log URL.
     *
     * @param url the URL
     * @return the agent ID, or null if not found
     */
    private static String extractAgentId(String url) {
        if (url == null) {
            return null;
        }
        Matcher matcher = AGENT_ID_PATTERN.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Checks if this badge format version is supported.
     *
     * @return true if the badge format is supported (e.g., "ra-badge1" or "ans-badge1")
     */
    public boolean isSupportedBadgeFormat() {
        if (badgeVersion == null) {
            return false;
        }
        String lowerVersion = badgeVersion.toLowerCase();
        return lowerVersion.startsWith("ra-badge") || lowerVersion.startsWith("ans-badge");
    }

    @Override
    public String toString() {
        return "RaBadgeRecord{" +
            "badgeVersion='" + badgeVersion + "'" +
            ", agentVersion='" + agentVersion + "'" +
            ", url='" + url + "'" +
            ", agentId='" + agentId + "'" +
            "}";
    }
}
