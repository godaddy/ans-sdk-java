package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.transparency.verification.CachingBadgeVerificationService;
import com.godaddy.ans.sdk.transparency.verification.ServerVerificationResult;
import com.godaddy.ans.sdk.transparency.verification.ServerVerifier;
import com.godaddy.ans.sdk.transparency.verification.VerificationStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Badge verification against the ANS transparency log, performed outside the TLS handshake.
 *
 * <p>Badge verification confirms that the server's certificate fingerprint matches
 * what's registered in the ANS transparency log (the "badge" or proof of registration):</p>
 * <ul>
 *   <li><b>Pre-verification</b>: Look up _ra-badge DNS record and fetch registration from transparency log</li>
 *   <li><b>Post-verification</b>: Compare actual certificate fingerprint against registration</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * ServerVerifier verificationService = BadgeVerificationService.create();
 * BadgeVerifier verifier = new BadgeVerifier(verificationService);
 *
 * // Pre-verify (before TLS handshake)
 * BadgeVerifier.BadgeExpectation expectation = verifier.preVerify("example.com").join();
 *
 * // ... TLS handshake happens ...
 *
 * // Post-verify (after TLS handshake)
 * VerificationResult result = verifier.postVerify("example.com", serverCert, expectation);
 * }</pre>
 */
public class BadgeVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(BadgeVerifier.class);

    private final ServerVerifier verificationService;
    private final Executor executor;

    /**
     * Badge expectation from pre-verification.
     *
     * @param expectedFingerprints the expected fingerprints from transparency log (empty if not registered)
     * @param isRegisteredAgent true if the host is a registered ANS agent
     * @param isDeprecated true if the registration is deprecated (still valid but should be updated)
     * @param warningMessage any warning message from the verification service
     * @param preVerificationFailed true if pre-verification failed (e.g., revoked/expired registration)
     */
    public record BadgeExpectation(
        List<String> expectedFingerprints,
        boolean isRegisteredAgent,
        boolean isDeprecated,
        String warningMessage,
        boolean preVerificationFailed
    ) {

        /**
         * Creates expectation for a non-ANS agent.
         *
         * @return an expectation indicating not an ANS agent
         */
        public static BadgeExpectation notAnsAgent() {
            return new BadgeExpectation(Collections.emptyList(), false, false, null, false);
        }

        /**
         * Creates expectation for a registered ANS agent with a single fingerprint.
         *
         * @param fingerprint the expected fingerprint
         * @param deprecated true if registration is deprecated
         * @param warning optional warning message
         * @return an expectation for a registered agent
         */
        public static BadgeExpectation registered(String fingerprint, boolean deprecated, String warning) {
            return new BadgeExpectation(
                fingerprint != null ? List.of(fingerprint) : Collections.emptyList(),
                true, deprecated, warning, false);
        }

        /**
         * Creates expectation for a registered ANS agent with multiple fingerprints.
         *
         * <p>During version rotation, multiple badge records may exist with different fingerprints.</p>
         *
         * @param fingerprints the expected fingerprints
         * @param deprecated true if registration is deprecated
         * @param warning optional warning message
         * @return an expectation for a registered agent
         */
        public static BadgeExpectation registered(List<String> fingerprints, boolean deprecated, String warning) {
            return new BadgeExpectation(
                fingerprints != null ? List.copyOf(fingerprints) : Collections.emptyList(),
                true, deprecated, warning, false);
        }

        /**
         * Creates expectation for a verification failure (e.g., revoked or expired registration).
         *
         * @param warning the failure reason
         * @return an expectation indicating failure
         */
        public static BadgeExpectation failed(String warning) {
            return new BadgeExpectation(Collections.emptyList(), false, false, warning, true);
        }
    }

    /**
     * Creates a Badge verifier using the shared ANS I/O executor.
     *
     * @param verificationService the server verification service (supports caching via
     *                            {@link CachingBadgeVerificationService})
     * @see AnsExecutors#sharedIoExecutor()
     */
    public BadgeVerifier(ServerVerifier verificationService) {
        this(verificationService, AnsExecutors.sharedIoExecutor());
    }

    /**
     * Creates a Badge verifier with a custom executor.
     *
     * @param verificationService the server verification service (supports caching via
     *                            {@link CachingBadgeVerificationService})
     * @param executor the executor for async transparency log operations
     */
    public BadgeVerifier(ServerVerifier verificationService, Executor executor) {
        this.verificationService = Objects.requireNonNull(verificationService,
            "Verification service cannot be null");
        this.executor = Objects.requireNonNull(executor, "Executor cannot be null");
    }

    /**
     * Pre-verifies by looking up the registration in the transparency log.
     *
     * <p>This should be called before the TLS handshake. The result can be cached
     * and used for multiple post-verification calls.</p>
     *
     * <p>During version rotation, multiple badge records may exist. This method
     * returns all valid fingerprints so post-verification can match against any.</p>
     *
     * @param hostname the hostname to verify
     * @return a future containing the badge expectation
     */
    public CompletableFuture<BadgeExpectation> preVerify(String hostname) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                LOGGER.debug("Badge pre-verify: Querying transparency log for {}", hostname);

                ServerVerificationResult result = verificationService.verifyServer(hostname);

                if (result.isNotAnsAgent()) {
                    LOGGER.debug("Badge pre-verify: {} is not a registered ANS agent", hostname);
                    return BadgeExpectation.notAnsAgent();
                }

                if (result.isSuccess()) {
                    List<String> fingerprints = result.getExpectedServerCertFingerprints();
                    boolean deprecated = result.getStatus() == VerificationStatus.DEPRECATED_OK;
                    String warning = result.getWarningMessage();

                    LOGGER.debug("Badge pre-verify: Found {} fingerprint(s) for {} (deprecated={})",
                            fingerprints.size(), hostname, deprecated);
                    return BadgeExpectation.registered(fingerprints, deprecated, warning);
                } else {
                    String warning = String.format("Verification failed: %s - %s",
                        result.getStatus(), result.getWarningMessage());
                    LOGGER.debug("Badge pre-verify: {} - {}", hostname, warning);
                    return BadgeExpectation.failed(warning);
                }
            } catch (Exception e) {
                LOGGER.warn("Badge pre-verify error for {}: {}", hostname, e.getMessage());
                return BadgeExpectation.failed("Error querying transparency log: " + e.getMessage());
            }
        }, executor);
    }

    /**
     * Post-verifies the server certificate against the pre-verified expectation.
     *
     * <p>During version rotation, multiple fingerprints may be expected. The certificate
     * is verified if it matches ANY of the expected fingerprints from ACTIVE or DEPRECATED
     * registrations.</p>
     *
     * @param hostname the hostname that was verified
     * @param serverCert the server certificate from the TLS handshake
     * @param expectation the expectation from pre-verification
     * @return the verification result
     */
    public VerificationResult postVerify(String hostname, X509Certificate serverCert, BadgeExpectation expectation) {
        Objects.requireNonNull(hostname, "Hostname cannot be null");
        Objects.requireNonNull(serverCert, "Server certificate cannot be null");
        Objects.requireNonNull(expectation, "Expectation cannot be null");

        // Check if pre-verification failed (e.g., revoked or expired registration)
        if (expectation.preVerificationFailed()) {
            LOGGER.warn("Badge post-verify: Pre-verification failed for {} - {}",
                hostname, expectation.warningMessage());
            return VerificationResult.error(
                VerificationResult.VerificationType.BADGE,
                expectation.warningMessage() != null
                    ? expectation.warningMessage()
                    : "Pre-verification failed for " + hostname);
        }

        if (!expectation.isRegisteredAgent()) {
            return VerificationResult.notFound(
                VerificationResult.VerificationType.BADGE,
                String.format("Host %s is not a registered ANS agent", hostname));
        }

        List<String> expectedFingerprints = expectation.expectedFingerprints();
        if (expectedFingerprints == null || expectedFingerprints.isEmpty()) {
            return VerificationResult.error(
                VerificationResult.VerificationType.BADGE,
                "Registration found but no certificate fingerprint available");
        }

        try {
            LOGGER.debug("Badge post-verify: Comparing certificate against {} expected fingerprint(s) for {}",
                expectedFingerprints.size(), hostname);

            String actualFingerprint = CertificateUtils.computeSha256Fingerprint(serverCert);

            // Check if actual fingerprint matches ANY of the expected fingerprints
            for (String expectedFingerprint : expectedFingerprints) {
                if (CertificateUtils.fingerprintMatches(actualFingerprint, expectedFingerprint)) {
                    String reason = "Certificate matches transparency log registration";
                    if (expectation.isDeprecated()) {
                        reason += " (registration is DEPRECATED - consider updating)";
                    }
                    if (expectedFingerprints.size() > 1) {
                        reason += String.format(" (matched 1 of %d registered fingerprints)",
                                expectedFingerprints.size());
                    }
                    LOGGER.debug("Badge post-verify: Certificate matches for {}", hostname);
                    return VerificationResult.success(
                        VerificationResult.VerificationType.BADGE,
                        actualFingerprint,
                        reason);
                }
            }

            // No match found
            LOGGER.warn("Badge post-verify: Certificate mismatch for {} (checked {} fingerprints)",
                hostname, expectedFingerprints.size());
            return VerificationResult.mismatch(
                VerificationResult.VerificationType.BADGE,
                actualFingerprint,
                expectedFingerprints.get(0));  // Report first expected for error message
        } catch (Exception e) {
            LOGGER.error("Badge post-verify error for {}: {}", hostname, e.getMessage());
            return VerificationResult.error(VerificationResult.VerificationType.BADGE, e);
        }
    }
}
