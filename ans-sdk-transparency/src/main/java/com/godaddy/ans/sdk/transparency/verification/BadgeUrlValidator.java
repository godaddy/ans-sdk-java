package com.godaddy.ans.sdk.transparency.verification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Validates badge URLs for security before fetching from the transparency log.
 *
 * <p>This validator enforces the following security rules:</p>
 * <ul>
 *   <li><b>HTTPS Required:</b> Badge URLs must use HTTPS</li>
 *   <li><b>Trusted Domains:</b> Only configured transparency log domains are accepted</li>
 *   <li><b>Standard Ports:</b> Only default HTTPS port (443) is allowed</li>
 *   <li><b>Valid Paths:</b> Only /v1/agents/{uuid} paths are accepted, no traversal</li>
 *   <li><b>No Query Parameters:</b> Query strings are not allowed</li>
 * </ul>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * // Create validator with specific trusted domains
 * BadgeUrlValidator validator = BadgeUrlValidator.builder()
 *     .addTrustedDomain("transparency.ans.godaddy.com")
 *     .addTrustedDomain("transparency.ans.ote-godaddy.com")
 *     .build();
 *
 * // Or use GoDaddy ANS defaults
 * BadgeUrlValidator validator = BadgeUrlValidator.withGoDaddyDefaults();
 *
 * ValidationResult result = validator.validate(badgeUrl);
 * if (!result.valid()) {
 *     log.warn("Invalid badge URL: {}", result.reason());
 * }
 * }</pre>
 */
public final class BadgeUrlValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(BadgeUrlValidator.class);

    /**
     * GoDaddy ANS transparency log domains (for use with {@link #withGoDaddyDefaults()}).
     */
    public static final List<String> GODADDY_ANS_DOMAINS = List.of(
        "transparency.ans.godaddy.com",      // Production
        "transparency.ans.ote-godaddy.com"   // OTE
    );

    /**
     * Configured trusted transparency log domains.
     */
    private final List<String> trustedDomains;

    /**
     * Creates a validator with the specified trusted domains.
     *
     * @param trustedDomains the list of trusted transparency log domains
     * @throws IllegalArgumentException if trustedDomains is null or empty
     */
    private BadgeUrlValidator(List<String> trustedDomains) {
        if (trustedDomains == null || trustedDomains.isEmpty()) {
            throw new IllegalArgumentException("At least one trusted domain must be configured");
        }
        // Store as lowercase, immutable copy
        this.trustedDomains = trustedDomains.stream()
            .map(String::toLowerCase)
            .toList();
    }

    /**
     * Creates a validator configured with the standard GoDaddy ANS transparency log domains.
     *
     * <p>This is a convenience factory method for the common case of using the
     * GoDaddy ANS transparency logs (production, OTE, and development).</p>
     *
     * @return a validator with GoDaddy ANS domains
     */
    public static BadgeUrlValidator withGoDaddyDefaults() {
        return new BadgeUrlValidator(GODADDY_ANS_DOMAINS);
    }

    /**
     * Creates a new builder for configuring trusted domains.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the configured trusted domains (unmodifiable).
     *
     * @return the list of trusted domains
     */
    public List<String> getTrustedDomains() {
        return Collections.unmodifiableList(trustedDomains);
    }

    /**
     * Builder for creating {@link BadgeUrlValidator} instances.
     *
     * <p>Example usage:</p>
     * <pre>{@code
     * BadgeUrlValidator validator = BadgeUrlValidator.builder()
     *     .addTrustedDomain("transparency.provider1.com")
     *     .addTrustedDomain("transparency.provider2.com")
     *     .build();
     * }</pre>
     */
    public static final class Builder {
        private final List<String> domains = new ArrayList<>();

        private Builder() {}

        /**
         * Adds a trusted domain to the validator.
         *
         * @param domain the domain to trust (e.g., "transparency.ans.godaddy.com")
         * @return this builder
         * @throws IllegalArgumentException if domain is null or blank
         */
        public Builder addTrustedDomain(String domain) {
            if (domain == null || domain.isBlank()) {
                throw new IllegalArgumentException("Domain cannot be null or blank");
            }
            domains.add(domain.trim());
            return this;
        }

        /**
         * Adds multiple trusted domains to the validator.
         *
         * @param domains the domains to trust
         * @return this builder
         */
        public Builder addTrustedDomains(List<String> domains) {
            if (domains != null) {
                for (String domain : domains) {
                    addTrustedDomain(domain);
                }
            }
            return this;
        }

        /**
         * Adds the standard GoDaddy ANS transparency log domains.
         *
         * @return this builder
         */
        public Builder addGoDaddyDefaults() {
            return addTrustedDomains(GODADDY_ANS_DOMAINS);
        }

        /**
         * Builds the validator with the configured domains.
         *
         * @return the configured validator
         * @throws IllegalStateException if no domains were added
         */
        public BadgeUrlValidator build() {
            if (domains.isEmpty()) {
                throw new IllegalStateException("At least one trusted domain must be configured");
            }
            return new BadgeUrlValidator(domains);
        }
    }

    /**
     * Valid badge URL path pattern: /v1/agents/{uuid}/ with optional trailing slash.
     * UUID format: lowercase hex with dashes (e.g., 6bf2b7a9-1383-4e33-a945-845f34af7526)
     */
    private static final Pattern VALID_PATH_PATTERN = Pattern.compile(
        "^/v1/agents/[a-f0-9-]+/?$",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * Pattern to detect path traversal attempts (including URL-encoded).
     */
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
        "\\.\\.|%2e%2e|%252e|\\\\",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * Result of URL validation.
     *
     * @param valid whether the URL is valid
     * @param reason the reason for rejection, or null if valid
     */
    public record ValidationResult(boolean valid, String reason) {

        /**
         * Creates a successful validation result.
         *
         * @return a valid result
         */
        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        /**
         * Creates a failed validation result.
         *
         * @param reason the reason for rejection
         * @return an invalid result
         */
        public static ValidationResult failure(String reason) {
            return new ValidationResult(false, reason);
        }
    }

    /**
     * Validates a badge URL.
     *
     * @param url the badge URL to validate
     * @return the validation result
     */
    public ValidationResult validate(String url) {
        if (url == null || url.isBlank()) {
            return ValidationResult.failure("URL is null or empty");
        }

        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            LOGGER.debug("Malformed URL: {}", url);
            return ValidationResult.failure("Malformed URL: " + e.getMessage());
        }

        // Validate scheme (HTTPS required)
        ValidationResult schemeResult = validateScheme(uri);
        if (!schemeResult.valid()) {
            return schemeResult;
        }

        // Validate domain (must be trusted transparency log)
        ValidationResult domainResult = validateDomain(uri);
        if (!domainResult.valid()) {
            return domainResult;
        }

        // Validate port (only default HTTPS port)
        ValidationResult portResult = validatePort(uri);
        if (!portResult.valid()) {
            return portResult;
        }

        // Validate path (must match /v1/agents/{uuid}, no traversal)
        ValidationResult pathResult = validatePath(uri, url);
        if (!pathResult.valid()) {
            return pathResult;
        }

        // Validate no query parameters
        ValidationResult queryResult = validateNoQuery(uri);
        if (!queryResult.valid()) {
            return queryResult;
        }

        return ValidationResult.success();
    }

    /**
     * Validates the URL scheme (HTTPS required).
     */
    private ValidationResult validateScheme(URI uri) {
        String scheme = uri.getScheme();
        if (scheme == null) {
            return ValidationResult.failure("URL has no scheme");
        }

        if ("https".equalsIgnoreCase(scheme)) {
            return ValidationResult.success();
        }

        return ValidationResult.failure("HTTPS required (got " + scheme + ")");
    }

    /**
     * Validates the domain (must be a trusted transparency log domain).
     */
    private ValidationResult validateDomain(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            return ValidationResult.failure("URL has no host");
        }

        if (trustedDomains.contains(host.toLowerCase())) {
            return ValidationResult.success();
        }

        return ValidationResult.failure("Untrusted domain: " + host);
    }

    /**
     * Validates the port (only default HTTPS port 443 allowed).
     */
    private ValidationResult validatePort(URI uri) {
        int port = uri.getPort();

        // No port specified = default port (443 for HTTPS) = OK
        if (port == -1) {
            return ValidationResult.success();
        }

        // Explicit port 443 for HTTPS = OK
        if (port == 443) {
            return ValidationResult.success();
        }

        return ValidationResult.failure("Non-standard port not allowed: " + port);
    }

    /**
     * Validates the path (must match /v1/agents/{uuid}, no traversal).
     */
    private ValidationResult validatePath(URI uri, String originalUrl) {
        String path = uri.getPath();
        if (path == null || path.isBlank()) {
            return ValidationResult.failure("URL has no path");
        }

        // Check for path traversal in original URL (before URL decoding)
        if (PATH_TRAVERSAL_PATTERN.matcher(originalUrl).find()) {
            return ValidationResult.failure("Path traversal detected in URL");
        }

        // Also check decoded path for traversal
        try {
            String decodedPath = URLDecoder.decode(path, StandardCharsets.UTF_8);
            if (decodedPath.contains("..") || decodedPath.contains("\\")) {
                return ValidationResult.failure("Path traversal detected in decoded path");
            }
        } catch (Exception e) {
            // Decoding failed, continue with original path check
            LOGGER.debug("URL decode failed for path: {}", path);
        }

        // Validate path matches expected pattern
        if (!VALID_PATH_PATTERN.matcher(path).matches()) {
            return ValidationResult.failure("Invalid path format (expected /v1/agents/{uuid})");
        }

        return ValidationResult.success();
    }

    /**
     * Validates that no query parameters are present.
     */
    private ValidationResult validateNoQuery(URI uri) {
        String query = uri.getQuery();
        if (query != null && !query.isBlank()) {
            return ValidationResult.failure("Query parameters not allowed in badge URL");
        }
        return ValidationResult.success();
    }
}
