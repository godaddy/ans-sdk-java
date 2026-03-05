package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Default implementation of {@link ConnectionVerifier} that composes DANE and Badge verifiers.
 *
 * <p>This implementation performs verification outside the TLS handshake:</p>
 * <ol>
 *   <li><b>Pre-verification</b>: Runs all enabled verifiers in parallel to gather expectations</li>
 *   <li><b>Post-verification</b>: Compares actual certificate against expectations</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
 *     .daneVerifier(new DaneVerifier(tlsaVerifier))
 *     .badgeVerifier(new BadgeVerifier(verificationService))
 *     .build();
 *
 * // Pre-verify (async, cacheable)
 * PreVerificationResult preResult = verifier.preVerify("example.com", 443).join();
 *
 * // ... TLS handshake happens with PKI-only validation ...
 *
 * // Post-verify (fast fingerprint comparison)
 * List<VerificationResult> results = verifier.postVerify("example.com", serverCert, preResult);
 *
 * // Check combined result
 * VerificationResult combined = verifier.combine(results, policy);
 * if (combined.shouldFail()) {
 *     throw new VerificationException(combined);
 * }
 * }</pre>
 */
public class DefaultConnectionVerifier implements ConnectionVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultConnectionVerifier.class);

    private final DaneVerifier daneVerifier;
    private final BadgeVerifier badgeVerifier;

    private DefaultConnectionVerifier(Builder builder) {
        this.daneVerifier = builder.daneVerifier;
        this.badgeVerifier = builder.badgeVerifier;
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public CompletableFuture<PreVerificationResult> preVerify(String hostname, int port) {
        LOGGER.debug("Pre-verifying {}:{}", hostname, port);

        // Run all pre-verifications in parallel
        CompletableFuture<DaneVerifier.PreVerifyResult> daneFuture = daneVerifier != null
            ? daneVerifier.preVerify(hostname, port)
            : CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of()));

        CompletableFuture<BadgeVerifier.BadgeExpectation> badgeFuture = badgeVerifier != null
            ? badgeVerifier.preVerify(hostname)
            : CompletableFuture.completedFuture(null);

        // Combine results
        return daneFuture.thenCombine(badgeFuture, (daneResult, badge) -> {
                PreVerificationResult.Builder builder = PreVerificationResult.builder(hostname, port);

                // Add DANE expectations and DNS error status
                builder.danePreVerifyResult(daneResult);

                // Add Badge expectation(s)
                if (badge != null) {
                    if (badge.isRegisteredAgent()) {
                        // During version rotation, multiple badge records may exist
                        builder.badgeFingerprints(badge.expectedFingerprints());
                    } else if (badge.preVerificationFailed()) {
                        // Capture pre-verification failure (e.g., revoked/expired registration)
                        builder.badgePreVerifyFailed(badge.warningMessage());
                    }
                }

                PreVerificationResult result = builder.build();
                LOGGER.debug("Pre-verification complete for {}:{}: {}", hostname, port, result);
                return result;
            });
    }

    @Override
    public List<VerificationResult> postVerify(String hostname, X509Certificate serverCert,
                                                PreVerificationResult preResult) {
        LOGGER.debug("Post-verifying {} with certificate", hostname);

        List<VerificationResult> results = new ArrayList<>();

        // DANE post-verification
        if (daneVerifier != null) {
            VerificationResult daneResult;
            if (preResult.daneDnsError()) {
                // DNS query failed - this is an ERROR, not NOT_FOUND
                daneResult = VerificationResult.error(
                    VerificationResult.VerificationType.DANE,
                    "DNS lookup failed: " + preResult.daneDnsErrorMessage());
                LOGGER.warn("DANE DNS error for {}: {}", hostname, preResult.daneDnsErrorMessage());
            } else {
                daneResult = daneVerifier.postVerify(
                    hostname, serverCert, preResult.daneExpectations());
            }
            results.add(daneResult);
            LOGGER.debug("DANE result for {}: {}", hostname, daneResult.status());
        }

        // Badge post-verification
        if (badgeVerifier != null) {
            BadgeVerifier.BadgeExpectation badgeExpectation;
            if (preResult.badgePreVerifyFailed()) {
                // Pre-verification failed (e.g., revoked/expired registration)
                badgeExpectation = BadgeVerifier.BadgeExpectation.failed(preResult.badgeFailureReason());
            } else if (preResult.hasBadgeExpectation()) {
                // During version rotation, multiple fingerprints may exist
                badgeExpectation = BadgeVerifier.BadgeExpectation.registered(
                    preResult.badgeFingerprints(), false, null);
            } else {
                badgeExpectation = BadgeVerifier.BadgeExpectation.notAnsAgent();
            }

            VerificationResult badgeResult = badgeVerifier.postVerify(hostname, serverCert, badgeExpectation);
            results.add(badgeResult);
            LOGGER.debug("Badge result for {}: {}", hostname, badgeResult.status());
        }

        return results;
    }

    @Override
    public VerificationResult combine(List<VerificationResult> results, VerificationPolicy policy) {
        // Check for failures based on policy
        for (VerificationResult result : results) {
            VerificationMode mode = getModeForType(result.type(), policy);

            // Check explicit failures (MISMATCH, ERROR)
            if (result.shouldFail()) {
                if (mode == VerificationMode.REQUIRED) {
                    LOGGER.warn("Verification failed (REQUIRED): {}", result);
                    return result; // Return the failing result
                } else {
                    LOGGER.warn("Verification issue (ADVISORY): {}", result);
                }
            }

            // Check NOT_FOUND - this is a failure when mode is REQUIRED, a warning when ADVISORY
            if (result.isNotFound()) {
                if (mode == VerificationMode.REQUIRED) {
                    LOGGER.warn("Verification not found but REQUIRED: {}", result);
                    // Convert NOT_FOUND to an error when REQUIRED
                    return VerificationResult.error(
                        result.type(),
                        "No " + result.type().name().toLowerCase()
                                + " record/registration found for verification (REQUIRED mode)");
                } else if (mode == VerificationMode.ADVISORY) {
                    LOGGER.warn("Verification not found (ADVISORY - continuing): {}", result);
                }
            }
        }

        // All required verifications passed - return success
        // Find a successful result to return, preferring Badge > DANE
        for (VerificationResult result : results) {
            if (result.isSuccess()) {
                return result;
            }
        }

        // No explicit success but no failures either (all NOT_FOUND with ADVISORY mode)
        return VerificationResult.skipped("No verification performed (no records/registrations found)");
    }

    private VerificationMode getModeForType(VerificationResult.VerificationType type, VerificationPolicy policy) {
        return switch (type) {
            case DANE -> policy.daneMode();
            case BADGE -> policy.badgeMode();
            case PKI_ONLY -> VerificationMode.DISABLED;
        };
    }

    /**
     * Builder for DefaultConnectionVerifier.
     */
    public static class Builder {
        private DaneVerifier daneVerifier;
        private BadgeVerifier badgeVerifier;

        private Builder() {
        }

        /**
         * Sets the DANE verifier.
         *
         * @param daneVerifier the DANE verifier (null to disable DANE)
         * @return this builder
         */
        public Builder daneVerifier(DaneVerifier daneVerifier) {
            this.daneVerifier = daneVerifier;
            return this;
        }

        /**
         * Sets the Badge verifier.
         *
         * @param badgeVerifier the Badge verifier (null to disable Badge)
         * @return this builder
         */
        public Builder badgeVerifier(BadgeVerifier badgeVerifier) {
            this.badgeVerifier = badgeVerifier;
            return this;
        }

        /**
         * Builds the DefaultConnectionVerifier.
         *
         * @return the built verifier
         */
        public DefaultConnectionVerifier build() {
            return new DefaultConnectionVerifier(this);
        }
    }
}
