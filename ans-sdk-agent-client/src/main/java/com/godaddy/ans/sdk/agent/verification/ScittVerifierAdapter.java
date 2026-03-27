package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.CwtClaims;
import com.godaddy.ans.sdk.transparency.scitt.DefaultScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.DefaultScittVerifier;
import com.godaddy.ans.sdk.transparency.scitt.RefreshDecision;
import com.godaddy.ans.sdk.transparency.scitt.ScittExpectation;
import com.godaddy.ans.sdk.transparency.scitt.ScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.ScittPreVerifyResult;
import com.godaddy.ans.sdk.transparency.scitt.ScittReceipt;
import com.godaddy.ans.sdk.transparency.scitt.ScittVerifier;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

/**
 * Adapter for SCITT verification in the agent client connection flow.
 *
 * <p>This class bridges the SCITT verification infrastructure in ans-sdk-transparency
 * with the connection verification flow in ans-sdk-agent-client.</p>
 *
 * <p>The TransparencyClient provides both root key fetching and domain configuration,
 * eliminating the need to manually synchronize SCITT domain settings.</p>
 */
public class ScittVerifierAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScittVerifierAdapter.class);

    private final TransparencyClient transparencyClient;
    private final ScittVerifier scittVerifier;
    private final ScittHeaderProvider headerProvider;
    private final Executor executor;

    /**
     * Creates a new adapter with custom components.
     *
     * <p>This constructor is package-private. Use {@link #builder()} to create instances.
     * The builder ensures proper configuration including clock skew tolerance.</p>
     *
     * @param transparencyClient the transparency client for root key fetching
     * @param scittVerifier the SCITT verifier
     * @param headerProvider the header provider for extracting SCITT artifacts
     * @param executor the executor for async operations
     */
    ScittVerifierAdapter(
            TransparencyClient transparencyClient,
            ScittVerifier scittVerifier,
            ScittHeaderProvider headerProvider,
            Executor executor) {
        this.transparencyClient = Objects.requireNonNull(transparencyClient, "transparencyClient cannot be null");
        this.scittVerifier = Objects.requireNonNull(scittVerifier, "scittVerifier cannot be null");
        this.headerProvider = Objects.requireNonNull(headerProvider, "headerProvider cannot be null");
        this.executor = Objects.requireNonNull(executor, "executor cannot be null");
    }

    /**
     * Pre-verifies SCITT artifacts from response headers.
     *
     * <p>This should be called after receiving HTTP response headers but before
     * post-verification of the TLS certificate. The domain is automatically
     * derived from the TransparencyClient configuration.</p>
     *
     * @param responseHeaders the HTTP response headers
     * @return future containing the pre-verification result
     */
    public CompletableFuture<ScittPreVerifyResult> preVerify(Map<String, String> responseHeaders) {

        // Step 1: extract artifacts synchronously — this is cheap and has no I/O
        Optional<ScittHeaderProvider.ScittArtifacts> artifactsOpt;
        try {
            artifactsOpt = headerProvider.extractArtifacts(responseHeaders);
        } catch (RuntimeException e) {
            LOGGER.error("SCITT artifact parsing error: {}", e.getMessage());
            return CompletableFuture.completedFuture(
                ScittPreVerifyResult.parseError("Artifact error: " + e.getMessage()));
        }

        if (artifactsOpt.isEmpty() || !artifactsOpt.get().isComplete()) {
            LOGGER.debug("SCITT headers not present or incomplete");
            return CompletableFuture.completedFuture(ScittPreVerifyResult.notPresent());
        }

        ScittHeaderProvider.ScittArtifacts artifacts = artifactsOpt.get();
        ScittReceipt receipt = artifacts.receipt();
        StatusToken token = artifacts.statusToken();

        // Step 2: fetch keys asynchronously — uses transparencyClient's configured domain
        return transparencyClient.getRootKeysAsync()
            .thenApplyAsync((Map<String, PublicKey> rootKeys) -> {
                try {
                    ScittExpectation expectation = scittVerifier.verify(receipt, token, rootKeys);

                    // Check if verification failed due to unknown key - may need cache refresh
                    if (expectation.isKeyNotFound()) {
                        return handleKeyNotFound(receipt, token, expectation);
                    }

                    LOGGER.debug("SCITT pre-verification result: {}", expectation.status());
                    return ScittPreVerifyResult.verified(expectation, receipt, token);
                } catch (RuntimeException e) {
                    LOGGER.error("SCITT verification error: {}", e.getMessage(), e);
                    return ScittPreVerifyResult.parseError("Verification error: " + e.getMessage());
                }
            }, executor)
            .exceptionally(e -> {
                Throwable cause = e instanceof CompletionException && e.getCause() != null
                    ? e.getCause() : e;
                LOGGER.error("SCITT pre-verification error: {}", cause.getMessage(), cause);
                return ScittPreVerifyResult.parseError("Pre-verification error: " + cause.getMessage());
            });
    }

    /**
     * Handles a key-not-found verification failure by attempting to refresh the cache.
     *
     * <p>This method implements secure cache refresh logic:</p>
     * <ul>
     *   <li>Extracts the artifact's issued-at timestamp</li>
     *   <li>Only refreshes if the artifact is newer than our cache</li>
     *   <li>Enforces a cooldown to prevent cache thrashing attacks</li>
     *   <li>Retries verification once with refreshed keys</li>
     * </ul>
     */
    private ScittPreVerifyResult handleKeyNotFound(
            ScittReceipt receipt,
            StatusToken token,
            ScittExpectation originalExpectation) {

        // Get the artifact's issued-at timestamp for refresh decision
        Instant artifactIssuedAt = getArtifactIssuedAt(receipt, token);
        if (artifactIssuedAt == null) {
            LOGGER.warn("Cannot determine artifact issued-at time, failing verification");
            return ScittPreVerifyResult.verified(originalExpectation, receipt, token);
        }

        LOGGER.debug("Key not found, checking if cache refresh is needed (artifact iat={})", artifactIssuedAt);

        // Attempt refresh with security checks
        RefreshDecision decision = transparencyClient.refreshRootKeysIfNeeded(artifactIssuedAt);

        switch (decision.action()) {
            case REJECT:
                // Artifact is invalid (too old or from future) - return original error
                LOGGER.warn("Cache refresh rejected: {}", decision.reason());
                return ScittPreVerifyResult.verified(originalExpectation, receipt, token);

            case DEFER:
                // Cooldown in effect - return temporary failure
                LOGGER.info("Cache refresh deferred: {}", decision.reason());
                return ScittPreVerifyResult.parseError("Verification deferred: " + decision.reason());

            case REFRESHED:
                // Retry verification with fresh keys
                LOGGER.info("Cache refreshed, retrying verification");
                Map<String, PublicKey> freshKeys = decision.keys();
                ScittExpectation retryExpectation = scittVerifier.verify(receipt, token, freshKeys);
                LOGGER.debug("Retry verification result: {}", retryExpectation.status());
                return ScittPreVerifyResult.verified(retryExpectation, receipt, token);

            default:
                // Should never happen
                return ScittPreVerifyResult.verified(originalExpectation, receipt, token);
        }
    }

    /**
     * Extracts the issued-at timestamp from the SCITT artifacts.
     *
     * <p>Prefers the status token's issued-at time since it's typically more recent.
     * Falls back to the receipt's CWT claims if available.</p>
     */
    private Instant getArtifactIssuedAt(ScittReceipt receipt, StatusToken token) {
        // Prefer token's issued-at (typically more recent)
        if (token.issuedAt() != null) {
            return token.issuedAt();
        }

        // Fall back to receipt's CWT claims
        if (receipt.protectedHeader() != null) {
            CwtClaims claims = receipt.protectedHeader().cwtClaims();
            if (claims != null && claims.issuedAtTime() != null) {
                return claims.issuedAtTime();
            }
        }

        return null;
    }
    /**
     * Post-verifies the server certificate against SCITT expectations.
     *
     * @param hostname the hostname being connected to
     * @param serverCert the server certificate from TLS handshake
     * @param preResult the result from pre-verification
     * @return the verification result
     */
    public VerificationResult postVerify(
            String hostname,
            X509Certificate serverCert,
            ScittPreVerifyResult preResult) {

        Objects.requireNonNull(hostname, "hostname cannot be null");
        Objects.requireNonNull(serverCert, "serverCert cannot be null");
        Objects.requireNonNull(preResult, "preResult cannot be null");

        // If SCITT was not present, return NOT_FOUND
        if (!preResult.isPresent()) {
            return VerificationResult.notFound(
                VerificationResult.VerificationType.SCITT,
                "SCITT headers not present in response");
        }

        ScittExpectation expectation = preResult.expectation();

        // If pre-verification failed, return error
        if (!expectation.isVerified()) {
            String reason = expectation.failureReason() != null
                ? expectation.failureReason()
                : "SCITT verification failed: " + expectation.status();
            LOGGER.warn("SCITT pre-verification failed for {}: {}", hostname, reason);
            return VerificationResult.error(VerificationResult.VerificationType.SCITT, reason);
        }

        // Verify certificate fingerprint
        ScittVerifier.ScittVerificationResult result =
            scittVerifier.postVerify(hostname, serverCert, expectation);

        if (result.success()) {
            LOGGER.debug("SCITT post-verification successful for {}", hostname);
            return VerificationResult.success(
                VerificationResult.VerificationType.SCITT,
                result.actualFingerprint(),
                "Certificate matches SCITT status token");
        } else {
            LOGGER.warn("SCITT post-verification failed for {}: {}", hostname, result.failureReason());
            return VerificationResult.mismatch(
                VerificationResult.VerificationType.SCITT,
                result.actualFingerprint(),
                expectation.validServerCertFingerprints().isEmpty()
                    ? "unknown"
                    : String.join(",", expectation.validServerCertFingerprints()));
        }
    }

    /**
     * Builder for ScittVerifierAdapter.
     */
    public static class Builder {
        private TransparencyClient transparencyClient;
        private Duration clockSkewTolerance = StatusToken.DEFAULT_CLOCK_SKEW;
        private Executor executor = AnsExecutors.sharedIoExecutor();

        /**
         * Sets the TransparencyClient for root key fetching and domain configuration.
         *
         * @param transparencyClient the transparency client (required)
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient transparencyClient) {
            this.transparencyClient = transparencyClient;
            return this;
        }

        /**
         * Sets the clock skew tolerance for token expiry checks.
         *
         * @param tolerance the clock skew tolerance (default: 60 seconds)
         * @return this builder
         */
        public Builder clockSkewTolerance(Duration tolerance) {
            this.clockSkewTolerance = tolerance;
            return this;
        }

        /**
         * Sets the executor for async operations.
         *
         * @param executor the executor
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = executor;
            return this;
        }

        /**
         * Builds the adapter.
         *
         * @return the configured adapter
         * @throws NullPointerException if transparencyClient is not set
         */
        public ScittVerifierAdapter build() {
            Objects.requireNonNull(transparencyClient, "transparencyClient is required");
            ScittVerifier verifier = new DefaultScittVerifier(clockSkewTolerance);
            ScittHeaderProvider headerProvider = new DefaultScittHeaderProvider();
            return new ScittVerifierAdapter(transparencyClient, verifier, headerProvider, executor);
        }
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
}
