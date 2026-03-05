package com.godaddy.ans.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Interface for verifying connections outside the TLS handshake.
 *
 * <p>This interface provides a clean separation between TLS certificate
 * validation (PKI) and additional verification (DANE, Badge):</p>
 *
 * <pre>
 * 1. Pre-verify (before TLS handshake) - can run async
 *    - Look up DANE TLSA record
 *    - Query transparency log for Badge
 *
 * 2. TLS handshake (PKI only) - fast, standard validation
 *
 * 3. Post-verify (after handshake) - compare actual cert to expectations
 *    - Verify against DANE expectation
 *    - Verify against Badge expectation
 * </pre>
 *
 * <h2>Benefits</h2>
 * <ul>
 *   <li>TLS handshake is fast (PKI only)</li>
 *   <li>Pre-verification can be async and cached</li>
 *   <li>Verification logic is testable in isolation</li>
 *   <li>Clear separation of concerns</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * ConnectionVerifier verifier = DefaultConnectionVerifier.builder()
 *     .daneVerifier(daneVerifier)
 *     .badgeVerifier(badgeVerifier)
 *     .build();
 *
 * // Before TLS handshake
 * PreVerificationResult preResult = verifier.preVerify("example.com", 443).join();
 *
 * // ... TLS handshake happens ...
 *
 * // After TLS handshake
 * List<VerificationResult> results = verifier.postVerify("example.com", serverCert, preResult);
 * }</pre>
 */
public interface ConnectionVerifier {

    /**
     * Pre-verifies a hostname before the TLS handshake.
     *
     * <p>This method gathers expectations from all enabled verification sources
     * (DANE, Badge) that will be used to verify the actual certificate
     * after the handshake.</p>
     *
     * <p>This method is async and can be called concurrently with other operations.
     * Results should be cached when possible.</p>
     *
     * @param hostname the hostname to verify
     * @param port the port number (used for DANE TLSA lookup)
     * @return a future containing the pre-verification result
     */
    CompletableFuture<PreVerificationResult> preVerify(String hostname, int port);

    /**
     * Post-verifies the server certificate against pre-verification expectations.
     *
     * <p>This method compares the actual server certificate from the TLS handshake
     * against the expectations gathered during pre-verification.</p>
     *
     *
     * @param hostname the hostname that was verified
     * @param serverCert the server certificate from the TLS handshake
     * @param preResult the pre-verification result
     * @return list of verification results (one per verification type)
     */
    List<VerificationResult> postVerify(String hostname, X509Certificate serverCert, PreVerificationResult preResult);

    /**
     * Returns a combined verification result from multiple individual results.
     *
     * <p>The combined result fails if any required verification failed.</p>
     *
     * @param results the individual verification results
     * @param policy the verification policy (determines which failures are fatal)
     * @return the combined result
     */
    VerificationResult combine(List<VerificationResult> results, com.godaddy.ans.sdk.agent.VerificationPolicy policy);
}
