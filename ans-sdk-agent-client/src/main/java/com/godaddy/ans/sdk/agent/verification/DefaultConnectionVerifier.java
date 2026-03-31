package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.ScittPreVerifyResult;
import com.godaddy.ans.sdk.transparency.verification.CachingBadgeVerificationService;
import com.godaddy.ans.sdk.transparency.verification.ServerVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    private final ScittVerifierAdapter scittVerifier;

    private DefaultConnectionVerifier(Builder builder) {
        this.daneVerifier = builder.daneVerifier;
        this.badgeVerifier = builder.badgeVerifier;
        this.scittVerifier = builder.scittVerifier;
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
     * Creates a DefaultConnectionVerifier from a verification policy.
     *
     * <p>Wires DANE, Badge, and SCITT verifiers based on which modes are enabled
     * in the policy. This is the recommended way to construct a verifier when
     * you don't need custom caching or service overrides.</p>
     *
     * @param policy the verification policy controlling which verifiers are enabled
     * @param transparencyClient the transparency client for SCITT verification, or null
     * @param daneVerifier the DANE TLSA verifier, or null to skip DANE regardless of policy
     * @return a configured verifier
     */
    public static DefaultConnectionVerifier fromPolicy(
            VerificationPolicy policy,
            TransparencyClient transparencyClient,
            DaneTlsaVerifier daneVerifier) {
        return fromPolicy(policy, transparencyClient, daneVerifier, null);
    }

    /**
     * Creates a DefaultConnectionVerifier from a verification policy with an optional
     * badge service override.
     *
     * <p>Use the {@code badgeServiceOverride} parameter when you need to share a cached
     * badge verification service across multiple verifier instances (e.g., in a factory
     * that creates verifiers per-connection).</p>
     *
     * @param policy the verification policy controlling which verifiers are enabled
     * @param transparencyClient the transparency client for SCITT verification, or null
     * @param daneVerifier the DANE TLSA verifier, or null to skip DANE regardless of policy
     * @param badgeServiceOverride optional pre-built badge service; if null, a new
     *                             {@link CachingBadgeVerificationService} is created
     * @return a configured verifier
     */
    public static DefaultConnectionVerifier fromPolicy(
            VerificationPolicy policy,
            TransparencyClient transparencyClient,
            DaneTlsaVerifier daneVerifier,
            ServerVerifier badgeServiceOverride) {
        Builder builder = builder();

        if (policy.daneMode() != VerificationMode.DISABLED && daneVerifier != null) {
            builder.daneVerifier(new DaneVerifier(daneVerifier));
        }

        if (policy.badgeMode() != VerificationMode.DISABLED) {
            ServerVerifier badgeService;
            if (badgeServiceOverride != null) {
                badgeService = badgeServiceOverride;
            } else if (transparencyClient != null) {
                badgeService = CachingBadgeVerificationService.create(transparencyClient);
            } else {
                throw new IllegalStateException(
                    "Badge verification is enabled but no TransparencyClient or badge service "
                    + "was provided. Supply a TransparencyClient with an explicit baseUrl.");
            }
            builder.badgeVerifier(new BadgeVerifier(badgeService));
        }

        if (policy.scittMode() != VerificationMode.DISABLED && transparencyClient != null) {
            builder.scittVerifier(ScittVerifierAdapter.builder()
                .transparencyClient(transparencyClient)
                .build());
        }

        return builder.build();
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
    public CompletableFuture<ScittPreVerifyResult> scittPreVerify(Map<String, String> responseHeaders) {
        if (scittVerifier == null) {
            return CompletableFuture.completedFuture(ScittPreVerifyResult.notPresent());
        }
        return scittVerifier.preVerify(responseHeaders);
    }

    @Override
    public List<VerificationResult> postVerify(String hostname, X509Certificate serverCert,
                                                PreVerificationResult preResult) {
        LOGGER.debug("Post-verifying {} with certificate", hostname);

        List<VerificationResult> results = new ArrayList<>();

        postVerifyDane(hostname, serverCert, preResult).ifPresent(results::add);
        postVerifyScitt(hostname, serverCert, preResult).ifPresent(results::add);
        postVerifyBadge(hostname, serverCert, preResult).ifPresent(results::add);

        return results;
    }

    /**
     * Performs DANE post-verification if DANE verifier is configured.
     */
    private Optional<VerificationResult> postVerifyDane(String hostname,
                                                                   X509Certificate serverCert,
                                                                   PreVerificationResult preResult) {
        if (daneVerifier == null) {
            return Optional.empty();
        }

        VerificationResult daneResult;
        if (preResult.daneDnsError()) {
            // DNS query failed - this is an ERROR, not NOT_FOUND
            daneResult = VerificationResult.error(
                VerificationResult.VerificationType.DANE,
                "DNS lookup failed: " + preResult.daneDnsErrorMessage());
            LOGGER.warn("DANE DNS error for {}: {}", hostname, preResult.daneDnsErrorMessage());
        } else {
            daneResult = daneVerifier.postVerify(hostname, serverCert, preResult.daneExpectations());
        }

        LOGGER.debug("DANE result for {}: {}", hostname, daneResult.status());
        return Optional.of(daneResult);
    }

    /**
     * Performs SCITT post-verification if SCITT verifier is configured.
     */
    private Optional<VerificationResult> postVerifyScitt(String hostname,
                                                                    X509Certificate serverCert,
                                                                    PreVerificationResult preResult) {
        if (scittVerifier == null) {
            return Optional.empty();
        }

        VerificationResult scittResult;
        if (preResult.hasScittExpectation()) {
            scittResult = scittVerifier.postVerify(hostname, serverCert, preResult.scittPreVerifyResult());
        } else {
            // SCITT verifier present but no SCITT artifacts in response
            scittResult = VerificationResult.notFound(
                VerificationResult.VerificationType.SCITT,
                "SCITT headers not present in response");
        }

        LOGGER.debug("SCITT result for {}: {}", hostname, scittResult.status());
        return Optional.of(scittResult);
    }

    /**
     * Performs Badge post-verification if Badge verifier is configured.
     */
    private Optional<VerificationResult> postVerifyBadge(String hostname,
                                                                    X509Certificate serverCert,
                                                                    PreVerificationResult preResult) {
        if (badgeVerifier == null) {
            return Optional.empty();
        }

        BadgeVerifier.BadgeExpectation badgeExpectation = buildBadgeExpectation(preResult);
        VerificationResult badgeResult = badgeVerifier.postVerify(hostname, serverCert, badgeExpectation);

        LOGGER.debug("Badge result for {}: {}", hostname, badgeResult.status());
        return Optional.of(badgeResult);
    }

    /**
     * Builds the badge expectation from the pre-verification result.
     */
    private BadgeVerifier.BadgeExpectation buildBadgeExpectation(PreVerificationResult preResult) {
        if (preResult.badgePreVerifyFailed()) {
            // Pre-verification failed (e.g., revoked/expired registration)
            return BadgeVerifier.BadgeExpectation.failed(preResult.badgeFailureReason());
        } else if (preResult.hasBadgeExpectation()) {
            // During version rotation, multiple fingerprints may exist
            return BadgeVerifier.BadgeExpectation.registered(preResult.badgeFingerprints(), false, null);
        } else {
            return BadgeVerifier.BadgeExpectation.notAnsAgent();
        }
    }

    @Override
    public VerificationResult combine(List<VerificationResult> results, VerificationPolicy policy) {
        CombineStrategy strategy = determineCombineStrategy(results, policy);

        LOGGER.debug("Combining results with strategy: {}", strategy.name());

        // Check for failures based on policy and strategy
        VerificationResult failure = checkForFailures(results, policy, strategy);
        if (failure != null) {
            return failure;
        }

        // All required verifications passed - return the best success result
        return selectSuccessResult(results, strategy);
    }

    /**
     * Determines the combine strategy based on results and policy.
     *
     * <p>Uses {@link VerificationPolicy#allowsScittFallbackToBadge()} as the single source
     * of truth for fallback policy. Runtime conditions (SCITT missing, badge succeeded)
     * are checked only when the policy permits fallback.</p>
     *
     * @see VerificationPolicy#allowsScittFallbackToBadge()
     */
    private CombineStrategy determineCombineStrategy(List<VerificationResult> results,
                                                      VerificationPolicy policy) {
        // Check policy-level fallback permission first
        if (!policy.allowsScittFallbackToBadge()) {
            return CombineStrategy.STANDARD;
        }

        // Policy allows fallback - check runtime conditions
        Optional<VerificationResult> scittResult = findResultByType(results,
            VerificationResult.VerificationType.SCITT);
        Optional<VerificationResult> badgeResult = findResultByType(results,
            VerificationResult.VerificationType.BADGE);

        boolean scittMissing = scittResult.map(VerificationResult::isNotFound).orElse(false);
        boolean badgeSucceeded = badgeResult.map(VerificationResult::isSuccess).orElse(false);

        if (scittMissing && badgeSucceeded) {
            LOGGER.info("SCITT headers not present, falling back to badge verification for audit trail");
            return CombineStrategy.SCITT_FALLBACK_TO_BADGE;
        }

        return CombineStrategy.STANDARD;
    }

    /**
     * Checks all results for failures based on policy and strategy.
     *
     * @return the first failure result, or null if no failures
     */
    private VerificationResult checkForFailures(List<VerificationResult> results,
                                                 VerificationPolicy policy,
                                                 CombineStrategy strategy) {
        for (VerificationResult result : results) {
            VerificationMode mode = getModeForType(result.type(), policy);

            // Skip SCITT NOT_FOUND when using fallback strategy
            if (strategy.shouldSkipScittNotFound()
                && result.type() == VerificationResult.VerificationType.SCITT
                && result.isNotFound()) {
                continue;
            }

            // Check explicit failures (MISMATCH, ERROR)
            // FALLBACK_ALLOWED is strict for actual failures -- fallback only applies to NOT_FOUND
            boolean isStrict = mode == VerificationMode.REQUIRED
                || mode == VerificationMode.FALLBACK_ALLOWED;
            if (result.shouldFail() && isStrict) {
                LOGGER.warn("Verification failed ({}): {}", mode, result);
                return result;
            } else if (result.shouldFail()) {
                LOGGER.warn("Verification issue (ADVISORY): {}", result);
            }

            // Check NOT_FOUND - failure when REQUIRED, warning when ADVISORY
            if (result.isNotFound() && mode == VerificationMode.REQUIRED) {
                LOGGER.warn("Verification not found but REQUIRED: {}", result);
                return VerificationResult.error(
                    result.type(),
                    "No " + result.type().name().toLowerCase()
                        + " record/registration found for verification (REQUIRED mode)");
            } else if (result.isNotFound() && mode == VerificationMode.ADVISORY) {
                LOGGER.warn("Verification not found (ADVISORY - continuing): {}", result);
            }
        }
        return null;
    }

    /**
     * Selects the best success result based on priority: SCITT > Badge > DANE.
     */
    private VerificationResult selectSuccessResult(List<VerificationResult> results,
                                                    CombineStrategy strategy) {
        // Priority order: SCITT > Badge > DANE
        return findSuccessByType(results, VerificationResult.VerificationType.SCITT)
            .or(() -> findSuccessByType(results, VerificationResult.VerificationType.BADGE)
                .map(badge -> annotateFallbackIfNeeded(badge, strategy)))
            .or(() -> findSuccessByType(results, VerificationResult.VerificationType.DANE))
            .orElseGet(() -> VerificationResult.skipped(
                "No verification performed (no records/registrations found)"));
    }

    /**
     * Annotates a badge result as a SCITT fallback if that strategy is in use.
     */
    private VerificationResult annotateFallbackIfNeeded(VerificationResult badge, CombineStrategy strategy) {
        if (strategy == CombineStrategy.SCITT_FALLBACK_TO_BADGE) {
            return VerificationResult.success(
                badge.type(),
                badge.actualFingerprint(),
                badge.reason() + " (SCITT fallback)");
        }
        return badge;
    }

    /**
     * Strategy for combining verification results.
     *
     * <p>This enum encapsulates the different behaviors needed when combining
     * multiple verification results into a final decision.</p>
     */
    private enum CombineStrategy {
        /**
         * Standard combining - each verification is evaluated independently
         * according to its mode (REQUIRED, ADVISORY, DISABLED).
         */
        STANDARD {
            @Override
            boolean shouldSkipScittNotFound() {
                return false;
            }
        },

        /**
         * SCITT fallback to Badge - when SCITT headers are missing but badge
         * verification succeeded, allow the badge result to satisfy the policy.
         *
         * <p>This strategy is used exclusively with {@link VerificationPolicy#SCITT_ENHANCED}
         * (scitt=REQUIRED, badge=ADVISORY) to support migration scenarios where
         * servers may not yet provide SCITT headers.</p>
         */
        SCITT_FALLBACK_TO_BADGE {
            @Override
            boolean shouldSkipScittNotFound() {
                return true;
            }
        };

        /**
         * Whether to skip SCITT NOT_FOUND results during failure checking.
         */
        abstract boolean shouldSkipScittNotFound();
    }

    /**
     * Finds a verification result by type.
     */
    private Optional<VerificationResult> findResultByType(List<VerificationResult> results,
                                                           VerificationResult.VerificationType type) {
        return results.stream()
            .filter(r -> r.type() == type)
            .findFirst();
    }

    /**
     * Finds a successful verification result by type.
     */
    private Optional<VerificationResult> findSuccessByType(List<VerificationResult> results,
                                                            VerificationResult.VerificationType type) {
        return results.stream()
            .filter(r -> r.type() == type && r.isSuccess())
            .findFirst();
    }

    private VerificationMode getModeForType(VerificationResult.VerificationType type, VerificationPolicy policy) {
        return switch (type) {
            case DANE -> policy.daneMode();
            case BADGE -> policy.badgeMode();
            case SCITT -> policy.scittMode();
            case PKI_ONLY -> VerificationMode.DISABLED;
        };
    }

    /**
     * Builder for DefaultConnectionVerifier.
     */
    public static class Builder {
        private DaneVerifier daneVerifier;
        private BadgeVerifier badgeVerifier;
        private ScittVerifierAdapter scittVerifier;

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
         * Sets the SCITT verifier.
         *
         * @param scittVerifier the SCITT verifier (null to disable SCITT)
         * @return this builder
         */
        public Builder scittVerifier(ScittVerifierAdapter scittVerifier) {
            this.scittVerifier = scittVerifier;
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
