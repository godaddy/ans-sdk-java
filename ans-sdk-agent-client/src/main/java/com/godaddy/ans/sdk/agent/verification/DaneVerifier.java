package com.godaddy.ans.sdk.agent.verification;

import com.godaddy.ans.sdk.concurrent.AnsExecutors;
import com.godaddy.ans.sdk.crypto.CertificateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * DANE/TLSA verification performed outside the TLS handshake.
 *
 * <p>This class extracts DANE verification logic from the TrustManager
 * to enable verification outside the handshake. It provides:</p>
 * <ul>
 *   <li><b>Pre-verification</b>: Look up TLSA record and extract expected hash</li>
 *   <li><b>Post-verification</b>: Compare actual certificate against expected hash</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * DaneVerifier verifier = new DaneVerifier(tlsaVerifier);
 *
 * // Pre-verify (before TLS handshake)
 * PreVerifyResult preResult = verifier.preVerify("example.com", 443).join();
 *
 * // ... TLS handshake happens ...
 *
 * // Post-verify (after TLS handshake)
 * VerificationResult result = verifier.postVerify("example.com", serverCert, preResult.expectations());
 * }</pre>
 */
public class DaneVerifier {

    /**
     * Result of DANE pre-verification, distinguishing between successful lookups
     * (with or without records) and DNS errors.
     */
    public static final class PreVerifyResult {
        private final List<DaneTlsaVerifier.TlsaExpectation> expectations;
        private final boolean dnsError;
        private final String errorMessage;

        private PreVerifyResult(List<DaneTlsaVerifier.TlsaExpectation> expectations,
                                boolean dnsError, String errorMessage) {
            this.expectations = expectations;
            this.dnsError = dnsError;
            this.errorMessage = errorMessage;
        }

        /**
         * Creates a successful result with the given expectations.
         *
         * @param expectations the TLSA expectations (may be empty if no records found)
         * @return a successful pre-verification result
         */
        public static PreVerifyResult success(List<DaneTlsaVerifier.TlsaExpectation> expectations) {
            return new PreVerifyResult(
                expectations != null ? expectations : List.of(),
                false,
                null
            );
        }

        /**
         * Creates a DNS error result.
         *
         * @param errorMessage description of the DNS error
         * @return a pre-verification result indicating DNS failure
         */
        public static PreVerifyResult dnsError(String errorMessage) {
            return new PreVerifyResult(List.of(), true, errorMessage);
        }

        /**
         * Returns the TLSA expectations from DNS lookup.
         *
         * @return list of expectations, empty if no records found or DNS error occurred
         */
        public List<DaneTlsaVerifier.TlsaExpectation> expectations() {
            return expectations;
        }

        /**
         * Returns true if a DNS error occurred during the lookup.
         *
         * @return true if DNS query failed
         */
        public boolean isDnsError() {
            return dnsError;
        }

        /**
         * Returns the error message if a DNS error occurred.
         *
         * @return error message, or null if no error
         */
        public String errorMessage() {
            return errorMessage;
        }

        /**
         * Returns true if TLSA records were found.
         *
         * @return true if expectations list is not empty
         */
        public boolean hasExpectations() {
            return !expectations.isEmpty();
        }

        @Override
        public String toString() {
            if (dnsError) {
                return "PreVerifyResult[dnsError=" + errorMessage + "]";
            }
            return "PreVerifyResult[expectations=" + expectations.size() + "]";
        }
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(DaneVerifier.class);

    private final DaneTlsaVerifier tlsaVerifier;
    private final Executor executor;

    /**
     * Creates a DANE verifier using the shared ANS I/O executor.
     *
     * @param tlsaVerifier the underlying TLSA verifier (should support caching)
     * @see AnsExecutors#sharedIoExecutor()
     */
    public DaneVerifier(DaneTlsaVerifier tlsaVerifier) {
        this(tlsaVerifier, AnsExecutors.sharedIoExecutor());
    }

    /**
     * Creates a DANE verifier with a custom executor.
     *
     * @param tlsaVerifier the underlying TLSA verifier (should support caching)
     * @param executor the executor for async DNS operations
     */
    public DaneVerifier(DaneTlsaVerifier tlsaVerifier, Executor executor) {
        this.tlsaVerifier = Objects.requireNonNull(tlsaVerifier, "TLSA verifier cannot be null");
        this.executor = Objects.requireNonNull(executor, "Executor cannot be null");
    }

    /**
     * Pre-verifies by looking up all TLSA records.
     *
     * <p>This should be called before the TLS handshake. The result contains all
     * TLSA expectations from DNS and should be passed to {@link #postVerify}.</p>
     *
     * <p>This method performs DNS-only operations and does NOT connect to the server.
     * The actual TLS connection should happen after this returns, and then
     * {@link #postVerify} should be called with the server certificate.</p>
     *
     * @param hostname the hostname to verify
     * @param port the port number (typically 443)
     * @return a future containing a PreVerifyResult with expectations or DNS error status
     */
    public CompletableFuture<PreVerifyResult> preVerify(String hostname, int port) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                LOGGER.debug("DANE pre-verify: Looking up TLSA records for {}:{} (DNS only)", hostname, port);

                // Single DNS query - no TLS connection
                List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    tlsaVerifier.getTlsaExpectations(hostname, port);

                if (expectations.isEmpty()) {
                    LOGGER.debug("DANE pre-verify: No TLSA records found for {}:{}", hostname, port);
                } else {
                    LOGGER.debug("DANE pre-verify: Found {} TLSA expectation(s) for {}:{}",
                        expectations.size(), hostname, port);
                }

                return PreVerifyResult.success(expectations);

            } catch (Exception e) {
                LOGGER.warn("DANE pre-verify DNS error for {}:{}: {}", hostname, port, e.getMessage());
                return PreVerifyResult.dnsError(e.getMessage());
            }
        }, executor);
    }

    /**
     * Pre-verifies by looking up all TLSA records, returning raw expectations list.
     *
     * <p>This is a convenience method that extracts the expectations list from the result.
     * For production use with REQUIRED mode, prefer using the {@link #preVerify(String, int)}
     * method directly to check for DNS errors.</p>
     *
     * @param hostname the hostname to verify
     * @param port the port number (typically 443)
     * @return a future containing all TLSA expectations (empty list if no records or DNS error)
     */
    public CompletableFuture<List<DaneTlsaVerifier.TlsaExpectation>> preVerifyExpectations(String hostname, int port) {
        return preVerify(hostname, port).thenApply(PreVerifyResult::expectations);
    }

    /**
     * Post-verifies the server certificate against the pre-verified expectations.
     *
     * <p>This should be called after the TLS handshake with the actual server certificate.
     * The method tries to match the certificate against ANY of the TLSA expectations,
     * supporting certificate rotation scenarios where multiple records exist.</p>
     *
     * @param hostname the hostname that was verified
     * @param serverCert the server certificate from the TLS handshake
     * @param expectations the TLSA expectations from pre-verification (empty list if no records)
     * @return the verification result
     */
    public VerificationResult postVerify(String hostname, X509Certificate serverCert,
                                         List<DaneTlsaVerifier.TlsaExpectation> expectations) {
        Objects.requireNonNull(hostname, "Hostname cannot be null");
        Objects.requireNonNull(serverCert, "Server certificate cannot be null");

        if (expectations == null || expectations.isEmpty()) {
            return VerificationResult.notFound(
                VerificationResult.VerificationType.DANE,
                String.format("No TLSA record for %s", hostname));
        }

        try {
            LOGGER.debug("DANE post-verify: Comparing certificate against {} TLSA record(s) for {}",
                expectations.size(), hostname);

            // Try matching against each expectation
            for (int i = 0; i < expectations.size(); i++) {
                DaneTlsaVerifier.TlsaExpectation expectation = expectations.get(i);

                byte[] certData = TlsaUtils.computeCertificateData(serverCert, expectation.selector(),
                        expectation.matchingType());
                byte[] expected = expectation.expectedData();
                if (certData != null && Arrays.equals(certData, expected)) {
                    String matchType = TlsaUtils.describeMatchType(expectation.selector(), expectation.matchingType());
                    String fingerprint = TlsaUtils.bytesToHex(certData);
                    LOGGER.debug("DANE post-verify: Certificate matches TLSA record {} ({}) for {}",
                        i + 1, matchType, hostname);
                    return VerificationResult.success(
                        VerificationResult.VerificationType.DANE,
                        fingerprint,
                        "TLSA record matches (" + matchType + ")");
                }
            }

            // No match found
            String actualFingerprint = CertificateUtils.computeSha256Fingerprint(serverCert);
            String expectedFingerprint = TlsaUtils.bytesToHex(expectations.get(0).expectedData());
            LOGGER.warn("DANE post-verify: Certificate did not match any of {} TLSA record(s) for {}",
                expectations.size(), hostname);
            return VerificationResult.mismatch(
                VerificationResult.VerificationType.DANE,
                actualFingerprint,
                expectedFingerprint);

        } catch (Exception e) {
            LOGGER.error("DANE post-verify error for {}: {}", hostname, e.getMessage());
            return VerificationResult.error(VerificationResult.VerificationType.DANE, e);
        }
    }
}
