package com.godaddy.ans.sdk.transparency.verification;

import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.dns.RaBadgeLookupService;
import com.godaddy.ans.sdk.transparency.dns.RaBadgeRecord;
import com.godaddy.ans.sdk.transparency.model.TransparencyLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Service for verifying ANS agents against the transparency log.
 *
 * <p>This service implements the verification flows described in AGENT_TO_AGENT_FLOW.md:</p>
 * <ul>
 *   <li><b>Server verification</b>: Verifies that a server is a registered ANS agent
 *       by looking up its ra-badge DNS record and checking the transparency log.</li>
 *   <li><b>Client verification</b>: Verifies that an mTLS client certificate belongs
 *       to a registered ANS agent.</li>
 * </ul>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * BadgeVerificationService verifier = BadgeVerificationService.builder()
 *     .transparencyClient(TransparencyClient.create())
 *     .build();
 *
 * // Verify a server before connecting
 * ServerVerificationResult result = verifier.verifyServer("agent.example.com");
 * if (result.isSuccess()) {
 *     // Proceed with connection, verify TLS cert fingerprint matches
 *     String expectedFingerprint = result.getExpectedServerCertFingerprint();
 * }
 *
 * // Verify a client certificate during mTLS handshake
 * ClientVerificationResult clientResult = verifier.verifyClient(clientCert);
 * if (clientResult.isSuccess()) {
 *     // Client is verified
 * }
 * }</pre>
 */
public final class BadgeVerificationService implements ServerVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(BadgeVerificationService.class);

    /**
     * Valid registration statuses that allow verification to proceed.
     */
    private static final Set<String> ACTIVE_STATUSES = Set.of("ACTIVE", "WARNING");

    /**
     * Registration status indicating deprecated but still acceptable.
     */
    private static final String DEPRECATED_STATUS = "DEPRECATED";

    /**
     * Invalid registration statuses that cause verification to fail.
     */
    private static final Set<String> INVALID_STATUSES = Set.of("REVOKED", "EXPIRED");

    /**
     * Pattern to extract version from ANS name.
     * ANS name format: ans://v{major}.{minor}.{patch}.{host} or ans://{version}.{host}
     * Example: ans://v1.0.0.agent.example.com -> 1.0.0
     */
    private static final Pattern ANS_VERSION_PATTERN = Pattern.compile(
        "^ans://v?(\\d+\\.\\d+\\.\\d+)\\.",
        Pattern.CASE_INSENSITIVE
    );

    private final TransparencyClient transparencyClient;
    private final RaBadgeLookupService raBadgeLookupService;
    private final BadgeUrlValidator badgeUrlValidator;
    private final Executor executor;

    private BadgeVerificationService(Builder builder) {
        this.transparencyClient = Objects.requireNonNull(
            builder.transparencyClient, "transparencyClient is required");
        this.raBadgeLookupService = builder.raBadgeLookupService != null
            ? builder.raBadgeLookupService
            : new RaBadgeLookupService();
        this.badgeUrlValidator = builder.badgeUrlValidator != null
            ? builder.badgeUrlValidator
            : BadgeUrlValidator.withGoDaddyDefaults();
        this.executor = builder.executor != null
            ? builder.executor
            : AnsExecutors.sharedIoExecutor();
    }

    /**
     * Verifies a server against the transparency log.
     *
     * <p>This method:</p>
     * <ol>
     *   <li>Looks up ALL _ra-badge TXT records for the hostname (supports version rotation)</li>
     *   <li>Fetches registrations from the transparency log in parallel</li>
     *   <li>Checks registration statuses</li>
     *   <li>Returns ALL expected server certificate fingerprints for comparison</li>
     * </ol>
     *
     * @param hostname the server hostname to verify
     * @return the verification result with all valid fingerprints
     */
    public ServerVerificationResult verifyServer(String hostname) {
        Objects.requireNonNull(hostname, "hostname is required");
        LOG.debug("Verifying server: {}", hostname);

        try {
            // Step 1: Look up ALL badge DNS records (tries _ans-badge first, falls back to _ra-badge)
            List<RaBadgeRecord> badges = raBadgeLookupService.lookupBadges(hostname);
            if (badges.isEmpty()) {
                LOG.debug("No badge record found for {}", hostname);
                return ServerVerificationResult.builder()
                    .status(VerificationStatus.NOT_ANS_AGENT)
                    .build();
            }

            LOG.debug("Found {} badge records for {}", badges.size(), hostname);

            // Step 2: Validate badge URLs for security and filter invalid ones
            List<RaBadgeRecord> validBadges = filterValidBadgeUrls(badges);
            if (validBadges.isEmpty()) {
                LOG.warn("All badge URLs invalid for {}", hostname);
                return ServerVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("All badge URLs failed validation")
                    .build();
            }

            // Step 3: Filter badges with valid agent IDs
            List<RaBadgeRecord> badgesWithIds = validBadges.stream()
                .filter(badge -> badge.agentId() != null && !badge.agentId().isBlank())
                .collect(Collectors.toList());

            if (badgesWithIds.isEmpty()) {
                LOG.warn("No badge records with valid agent IDs for {}", hostname);
                return ServerVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("Invalid badge records: missing agent IDs")
                    .build();
            }

            // Step 4: Fetch all registrations in parallel
            LOG.debug("Fetching {} registrations in parallel for server verification", badgesWithIds.size());
            List<FetchResult> fetchResults = fetchRegistrationsInParallel(badgesWithIds);

            // Step 5: Evaluate all registrations and collect valid fingerprints
            return evaluateServerRegistrations(fetchResults);

        } catch (Exception e) {
            LOG.error("Failed to verify server {}: {}", hostname, e.getMessage());
            return ServerVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("Lookup failed: " + e.getMessage())
                .build();
        }
    }

    /**
     * Verifies a client certificate against the transparency log.
     *
     * <p>This method:</p>
     * <ol>
     *   <li>Extracts the FQDN from the client certificate (DNS SAN or CN)</li>
     *   <li>Extracts the ANS name from the client certificate (URI SAN)</li>
     *   <li>Looks up the _ra-badge TXT record for the FQDN</li>
     *   <li>Fetches the registration(s) from the transparency log</li>
     *   <li>Matches the certificate fingerprint and ANS name</li>
     * </ol>
     *
     * @param clientCert the client certificate to verify
     * @return the verification result
     */
    public ClientVerificationResult verifyClient(X509Certificate clientCert) {
        Objects.requireNonNull(clientCert, "clientCert is required");
        LOG.debug("Verifying client certificate: {}", clientCert.getSubjectX500Principal());

        try {
            // Step 1: Extract FQDN from certificate (for DNS lookup)
            Optional<String> fqdnOpt = CertificateUtils.extractFqdn(clientCert);
            if (fqdnOpt.isEmpty()) {
                LOG.warn("Client certificate has no FQDN (no DNS SAN or CN)");
                return ClientVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("Certificate has no FQDN")
                    .build();
            }
            String fqdn = fqdnOpt.get();

            // Step 2: Extract CN from certificate (for agent.host matching per Section 4.4)
            String certCn = CertificateUtils.getCommonName(clientCert);

            // Step 3: Extract ANS name from certificate (required per Section 4.4)
            Optional<String> certAnsName = CertificateUtils.extractAnsName(clientCert);

            // Step 4: Extract version from ANS name for efficient badge filtering
            String certVersion = certAnsName.map(this::extractVersionFromAnsName).orElse(null);

            // Step 5: Compute client certificate fingerprint
            String clientFingerprint = CertificateUtils.computeSha256Fingerprint(clientCert);

            // Step 6: Look up badge DNS records (may have multiple for version rotation)
            List<RaBadgeRecord> badges = raBadgeLookupService.lookupBadges(fqdn);
            if (badges.isEmpty()) {
                LOG.debug("No badge record found for {}", fqdn);
                return ClientVerificationResult.builder()
                    .status(VerificationStatus.NOT_ANS_AGENT)
                    .build();
            }

            // Step 7: Validate badge URLs for security and filter invalid ones
            List<RaBadgeRecord> validBadges = filterValidBadgeUrls(badges);
            if (validBadges.isEmpty()) {
                LOG.warn("All badge URLs invalid for {}", fqdn);
                return ClientVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("All badge URLs failed validation")
                    .build();
            }

            // Step 8: Filter badges by version to reduce TL API calls during version rotation
            List<RaBadgeRecord> filteredBadges = filterBadgesByVersion(validBadges, certVersion);
            if (filteredBadges.isEmpty()) {
                // Fall back to all valid badges if no version match (backwards compatibility)
                LOG.debug("No badges match version {}, checking all {} valid badges", certVersion, validBadges.size());
                filteredBadges = validBadges;
            } else {
                LOG.debug("Filtered {} valid badges to {} matching version {}",
                    validBadges.size(), filteredBadges.size(), certVersion);
            }

            // Step 9: Check each registration for matching fingerprint, CN, and ANS name
            return findMatchingClientRegistration(filteredBadges, clientFingerprint, certAnsName.orElse(null), certCn);

        } catch (Exception e) {
            LOG.error("Failed to verify client: {}", e.getMessage());
            return ClientVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("Lookup failed: " + e.getMessage())
                .build();
        }
    }

    /**
     * Evaluates multiple server registrations and collects all valid fingerprints.
     *
     * <p>This method processes all fetch results and returns a combined result with
     * all valid fingerprints from ACTIVE or DEPRECATED registrations.</p>
     */
    private ServerVerificationResult evaluateServerRegistrations(List<FetchResult> fetchResults) {
        List<String> activeFingerprints = new ArrayList<>();
        List<String> deprecatedFingerprints = new ArrayList<>();
        TransparencyLog firstActiveRegistration = null;
        TransparencyLog firstDeprecatedRegistration = null;
        TransparencyLog firstInvalidRegistration = null;
        String agentHost = null;
        boolean hasWarning = false;
        String lastInvalidStatus = null;
        String lastErrorMessage = null;

        for (FetchResult fetchResult : fetchResults) {
            if (!fetchResult.isSuccess()) {
                // Track the last error message for diagnostics
                if (fetchResult.error() != null) {
                    lastErrorMessage = fetchResult.error().getMessage();
                }
                continue;
            }

            TransparencyLog registration = fetchResult.registration();
            String status = registration.getStatus();
            String fingerprint = registration.getServerCertFingerprint();

            if (fingerprint == null || fingerprint.isBlank()) {
                LOG.debug("Skipping registration with no fingerprint");
                continue;
            }

            if (ACTIVE_STATUSES.contains(status)) {
                activeFingerprints.add(fingerprint);
                if (firstActiveRegistration == null) {
                    firstActiveRegistration = registration;
                    agentHost = registration.getAgentHost();
                }
                if ("WARNING".equals(status)) {
                    hasWarning = true;
                }
                LOG.debug("Found ACTIVE registration with fingerprint: {}...",
                    fingerprint.length() > 20 ? fingerprint.substring(0, 20) : fingerprint);
            } else if (DEPRECATED_STATUS.equals(status)) {
                                deprecatedFingerprints.add(fingerprint);
                if (firstDeprecatedRegistration == null) {
                    firstDeprecatedRegistration = registration;
                    if (agentHost == null) {
                        agentHost = registration.getAgentHost();
                    }
                }
                LOG.debug("Found DEPRECATED registration with fingerprint: {}...",
                    fingerprint.length() > 20 ? fingerprint.substring(0, 20) : fingerprint);
            } else {
                // INVALID_STATUSES (REVOKED, EXPIRED) or unknown status
                if (firstInvalidRegistration == null) {
                    firstInvalidRegistration = registration;
                }
                lastInvalidStatus = status;
                LOG.debug("Skipping registration with invalid/unknown status: {}", status);
            }
        }

        // Return result with all valid fingerprints
        if (!activeFingerprints.isEmpty()) {
            // Combine active and deprecated fingerprints (active takes priority)
            List<String> allFingerprints = new ArrayList<>(activeFingerprints);
            allFingerprints.addAll(deprecatedFingerprints);

            LOG.debug("Server verification succeeded with {} active and {} deprecated fingerprints",
                activeFingerprints.size(), deprecatedFingerprints.size());

            ServerVerificationResult.Builder builder = ServerVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .registration(firstActiveRegistration)
                .expectedServerCertFingerprints(allFingerprints)
                .expectedAgentHost(agentHost);

            if (hasWarning) {
                builder.warningMessage("One or more registrations have WARNING status");
            }
            return builder.build();
        }

        if (!deprecatedFingerprints.isEmpty()) {
            LOG.debug("Server verification succeeded with {} deprecated fingerprints",
                deprecatedFingerprints.size());

            return ServerVerificationResult.builder()
                .status(VerificationStatus.DEPRECATED_OK)
                .registration(firstDeprecatedRegistration)
                .expectedServerCertFingerprints(deprecatedFingerprints)
                .expectedAgentHost(agentHost)
                .warningMessage("All registrations are deprecated")
                .build();
        }

        // All registrations were invalid/unknown status or no valid fingerprints found
        if (lastInvalidStatus != null && firstInvalidRegistration != null) {
            LOG.warn("All server registrations have invalid status: {}", lastInvalidStatus);
            String warningMessage = INVALID_STATUSES.contains(lastInvalidStatus)
                ? "Registration status: " + lastInvalidStatus
                : "Unknown registration status: " + lastInvalidStatus;
            return ServerVerificationResult.builder()
                .status(VerificationStatus.REGISTRATION_INVALID)
                .registration(firstInvalidRegistration)
                .warningMessage(warningMessage)
                .build();
        }

        // All fetches failed - include the last error message for diagnostics
        String warningMessage = "Failed to fetch any valid registrations";
        if (lastErrorMessage != null) {
            warningMessage += ": " + lastErrorMessage;
        }

        return ServerVerificationResult.builder()
            .status(VerificationStatus.LOOKUP_FAILED)
            .warningMessage(warningMessage)
            .build();
    }

    /**
     * Result of fetching a registration from the transparency log.
     */
    private record FetchResult(
            RaBadgeRecord badge,
            TransparencyLog registration,
            Exception error
    ) {
        static FetchResult success(RaBadgeRecord badge, TransparencyLog registration) {
            return new FetchResult(badge, registration, null);
        }

        static FetchResult failure(RaBadgeRecord badge, Exception error) {
            return new FetchResult(badge, null, error);
        }

        boolean isSuccess() {
            return registration != null;
        }
    }

    /**
     * Finds a matching client registration from the given badges.
     *
     * <p>This method fetches all registrations in parallel for performance,
     * then processes them in order to find the best match.</p>
     */
    private ClientVerificationResult findMatchingClientRegistration(
            List<RaBadgeRecord> badges,
            String clientFingerprint,
            String certAnsName,
            String certCn) {

        // Filter badges with valid agent IDs
        List<RaBadgeRecord> validBadges = badges.stream()
            .filter(badge -> badge.agentId() != null && !badge.agentId().isBlank())
            .collect(Collectors.toList());

        if (validBadges.isEmpty()) {
            return ClientVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("No valid badge records with agent IDs")
                .build();
        }

        // Fetch all registrations in parallel
        LOG.debug("Fetching {} registrations in parallel", validBadges.size());
        List<FetchResult> fetchResults = fetchRegistrationsInParallel(validBadges);

        // Process results in order to find the best match
        return processFetchResults(fetchResults, clientFingerprint, certAnsName, certCn);
    }

    /**
     * Fetches registrations for all badges in parallel.
     */
    private List<FetchResult> fetchRegistrationsInParallel(List<RaBadgeRecord> badges) {
        // Create futures for all badge lookups
        List<CompletableFuture<FetchResult>> futures = badges.stream()
            .map(badge -> CompletableFuture.supplyAsync(() -> {
                try {
                    TransparencyLog registration = transparencyClient.getAgentTransparencyLog(badge.agentId());
                    return FetchResult.success(badge, registration);
                } catch (Exception e) {
                    LOG.debug("Failed to fetch registration for agent {}: {}", badge.agentId(), e.getMessage());
                    return FetchResult.failure(badge, e);
                }
            }, executor))
            .toList();

        // Wait for all futures to complete and collect results
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        return futures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
    }

    /**
     * Processes fetch results to find the best matching registration.
     */
    private ClientVerificationResult processFetchResults(
            List<FetchResult> fetchResults,
            String clientFingerprint,
            String certAnsName,
            String certCn) {

        TransparencyLog activeMatch = null;
        TransparencyLog deprecatedMatch = null;
        TransparencyLog invalidMatch = null;
        String invalidStatus = null;
        TransparencyLog lastRegistration = null;
        String lastMismatchReason = null;

        for (FetchResult fetchResult : fetchResults) {
            if (!fetchResult.isSuccess()) {
                continue;
            }

            TransparencyLog registration = fetchResult.registration();
            lastRegistration = registration;

            String expectedFingerprint = registration.getIdentityCertFingerprint();
            String expectedAnsName = registration.getAnsName();
            String expectedAgentHost = registration.getAgentHost();
            String status = registration.getStatus();
            String agentId = fetchResult.badge().agentId();

            // Check fingerprint match (required per Section 4.4)
            boolean fingerprintMatch = CertificateUtils.fingerprintMatches(
                clientFingerprint, expectedFingerprint);

            if (!fingerprintMatch) {
                LOG.debug("Fingerprint mismatch for agent {}: expected={}, actual={}",
                    agentId, expectedFingerprint, clientFingerprint);
                lastMismatchReason = "fingerprint";
                continue;
            }

            // Check CN matches agent.host (required per Section 4.4)
            if (certCn != null && expectedAgentHost != null
                    && !certCn.equalsIgnoreCase(expectedAgentHost)) {
                LOG.debug("Hostname mismatch for agent {}: expected={}, actual={}",
                    agentId, expectedAgentHost, certCn);
                lastMismatchReason = "hostname";
                continue;
            }

            // Check ANS name match (required per Section 4.4)
            if (certAnsName != null && expectedAnsName != null
                    && !certAnsName.equals(expectedAnsName)) {
                LOG.debug("ANS name mismatch for agent {}: expected={}, actual={}",
                    agentId, expectedAnsName, certAnsName);
                lastMismatchReason = "ansname";
                continue;
            }

            // All three checks passed - check status
            if (ACTIVE_STATUSES.contains(status)) {
                activeMatch = registration;
                break; // Active match is best, stop searching
            } else if (DEPRECATED_STATUS.equals(status) && deprecatedMatch == null) {
                deprecatedMatch = registration;
                // Continue searching for an active match
            } else if (INVALID_STATUSES.contains(status) && invalidMatch == null) {
                // Registration matches but has invalid status (EXPIRED, REVOKED)
                invalidMatch = registration;
                invalidStatus = status;
                LOG.debug("Found matching registration with {} status for agent {}", status, agentId);
            }
        }

        // Return the best match found
        if (activeMatch != null) {
            LOG.debug("Client verification succeeded with ACTIVE registration");
            return ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .registration(activeMatch)
                .expectedIdentityCertFingerprint(activeMatch.getIdentityCertFingerprint())
                .expectedAnsName(activeMatch.getAnsName())
                .expectedAgentHost(activeMatch.getAgentHost())
                .build();
        }

        if (deprecatedMatch != null) {
            LOG.debug("Client verification succeeded with DEPRECATED registration");
            return ClientVerificationResult.builder()
                .status(VerificationStatus.DEPRECATED_OK)
                .registration(deprecatedMatch)
                .expectedIdentityCertFingerprint(deprecatedMatch.getIdentityCertFingerprint())
                .expectedAnsName(deprecatedMatch.getAnsName())
                .expectedAgentHost(deprecatedMatch.getAgentHost())
                .warningMessage("Registration is deprecated")
                .build();
        }

        // Registration matched but has invalid status (EXPIRED, REVOKED)
        if (invalidMatch != null) {
            LOG.warn("Client verification failed: registration status is {}", invalidStatus);
            return ClientVerificationResult.builder()
                .status(VerificationStatus.REGISTRATION_INVALID)
                .registration(invalidMatch)
                .expectedIdentityCertFingerprint(invalidMatch.getIdentityCertFingerprint())
                .expectedAnsName(invalidMatch.getAnsName())
                .expectedAgentHost(invalidMatch.getAgentHost())
                .warningMessage("Registration status: " + invalidStatus)
                .build();
        }

        // No match found - return appropriate mismatch status
        if (lastRegistration != null) {
            VerificationStatus mismatchStatus;
            String message;

            if ("hostname".equals(lastMismatchReason)) {
                mismatchStatus = VerificationStatus.HOSTNAME_MISMATCH;
                message = "Certificate CN does not match agent.host";
            } else if ("ansname".equals(lastMismatchReason)) {
                mismatchStatus = VerificationStatus.ANS_NAME_MISMATCH;
                message = "Certificate URI SAN does not match ansName";
            } else {
                mismatchStatus = VerificationStatus.FINGERPRINT_MISMATCH;
                message = "Certificate fingerprint does not match registration";
            }

            LOG.warn("Client verification failed: {}", message);
            return ClientVerificationResult.builder()
                .status(mismatchStatus)
                .registration(lastRegistration)
                .expectedIdentityCertFingerprint(lastRegistration.getIdentityCertFingerprint())
                .expectedAnsName(lastRegistration.getAnsName())
                .expectedAgentHost(lastRegistration.getAgentHost())
                .warningMessage(message)
                .build();
        }

        return ClientVerificationResult.builder()
            .status(VerificationStatus.LOOKUP_FAILED)
            .warningMessage("Failed to fetch any registrations")
            .build();
    }

    /**
     * Extracts the version from an ANS name.
     *
     * @param ansName the ANS name (e.g., "ans://v1.0.0.agent.example.com")
     * @return the version (e.g., "1.0.0"), or null if not found
     */
    private String extractVersionFromAnsName(String ansName) {
        if (ansName == null) {
            return null;
        }
        Matcher matcher = ANS_VERSION_PATTERN.matcher(ansName);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Filters badges to only those with valid URLs.
     *
     * <p>This security check ensures badge URLs point to trusted transparency log
     * domains before making any network requests.</p>
     *
     * @param badges the list of badges to filter
     * @return list of badges with valid URLs
     */
    private List<RaBadgeRecord> filterValidBadgeUrls(List<RaBadgeRecord> badges) {
        if (badges == null) {
            return List.of();
        }
        List<RaBadgeRecord> validBadges = new ArrayList<>();
        for (RaBadgeRecord badge : badges) {
            BadgeUrlValidator.ValidationResult result = badgeUrlValidator.validate(badge.url());
            if (result.valid()) {
                validBadges.add(badge);
            } else {
                LOG.debug("Skipping badge with invalid URL: {}", result.reason());
            }
        }
        return validBadges;
    }

    /**
     * Filters badges to only those matching the specified version.
     *
     * <p>This optimization reduces transparency log API calls during version rotation
     * by only fetching registrations for badges that match the certificate version.</p>
     *
     * @param badges the list of badges to filter
     * @param version the version to match (may be null)
     * @return filtered list, or empty if no matches (caller should fall back to all badges)
     */
    private List<RaBadgeRecord> filterBadgesByVersion(List<RaBadgeRecord> badges, String version) {
        if (version == null || badges == null) {
            return List.of();
        }
        return badges.stream()
            .filter(badge -> version.equals(badge.agentVersion()))
            .collect(Collectors.toList());
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a service with default configuration.
     *
     * @return a new service instance
     */
    public static BadgeVerificationService create() {
        return builder()
            .transparencyClient(TransparencyClient.create())
            .build();
    }

    /**
     * Builder for BadgeVerificationService.
     */
    public static final class Builder {
        private TransparencyClient transparencyClient;
        private RaBadgeLookupService raBadgeLookupService;
        private BadgeUrlValidator badgeUrlValidator;
        private Executor executor;

        private Builder() {
        }

        /**
         * Sets the transparency client to use for fetching registrations.
         *
         * @param transparencyClient the transparency client
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient transparencyClient) {
            this.transparencyClient = transparencyClient;
            return this;
        }

        /**
         * Sets a custom badge lookup service.
         *
         * <p>This is primarily useful for testing.</p>
         *
         * @param raBadgeLookupService the lookup service
         * @return this builder
         */
        public Builder raBadgeLookupService(RaBadgeLookupService raBadgeLookupService) {
            this.raBadgeLookupService = raBadgeLookupService;
            return this;
        }

        /**
         * Sets a custom badge URL validator.
         *
         * <p>This is primarily useful for testing.</p>
         *
         * @param badgeUrlValidator the URL validator
         * @return this builder
         */
        public Builder badgeUrlValidator(BadgeUrlValidator badgeUrlValidator) {
            this.badgeUrlValidator = badgeUrlValidator;
            return this;
        }

        /**
         * Sets a custom executor for parallel registration lookups.
         *
         * <p>If not specified, a shared bounded thread pool is used.</p>
         *
         * @param executor the executor for async operations
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = executor;
            return this;
        }

        /**
         * Builds the service.
         *
         * @return the configured service
         */
        public BadgeVerificationService build() {
            return new BadgeVerificationService(this);
        }
    }
}