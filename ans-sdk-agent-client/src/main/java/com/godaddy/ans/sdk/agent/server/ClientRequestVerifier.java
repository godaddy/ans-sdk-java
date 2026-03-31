package com.godaddy.ans.sdk.agent.server;

import com.godaddy.ans.sdk.agent.VerificationPolicy;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Server-side verifier for incoming client requests.
 *
 * <p>This interface provides a high-level API for MCP servers (and other server
 * implementations) to verify that incoming client requests are from legitimate
 * ANS-registered agents.</p>
 *
 * <p>Verification involves:</p>
 * <ol>
 *   <li>Extracting SCITT artifacts (receipt and status token) from request headers</li>
 *   <li>Verifying the cryptographic signatures on the artifacts</li>
 *   <li>Checking the status token hasn't expired</li>
 *   <li>Matching the client's mTLS certificate fingerprint against the
 *       {@code validIdentityCertFingerprints} in the status token</li>
 * </ol>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * ClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
 *     .scittVerifier(scittVerifierAdapter)
 *     .build();
 *
 * // In request handler
 * X509Certificate clientCert = (X509Certificate) sslSession.getPeerCertificates()[0];
 * Map<String, String> headers = extractHeaders(request);
 *
 * ClientRequestVerificationResult result = verifier
 *     .verify(clientCert, headers, VerificationPolicy.SCITT_REQUIRED)
 *     .join();
 *
 * if (!result.verified()) {
 *     return Response.status(403)
 *         .entity("Client verification failed: " + result.errors())
 *         .build();
 * }
 *
 * // Proceed with verified agent identity
 * String agentId = result.agentId();
 * }</pre>
 *
 * @see DefaultClientRequestVerifier
 * @see ClientRequestVerificationResult
 */
public interface ClientRequestVerifier {

    /**
     * Verifies an incoming client request.
     *
     * <p>This method extracts SCITT artifacts from the request headers, verifies
     * their signatures, and matches the client certificate fingerprint against
     * the status token's identity certificate fingerprints.</p>
     *
     * @param clientCert the client's X.509 certificate from mTLS handshake
     * @param requestHeaders the HTTP request headers (must include SCITT headers).
     *        Header keys must be lowercase (e.g., {@code x-scitt-receipt}, {@code x-ans-status-token}).
     * @param policy the verification policy to apply
     * @return a future that completes with the verification result
     * @throws NullPointerException if any parameter is null
     */
    CompletableFuture<ClientRequestVerificationResult> verify(
        X509Certificate clientCert,
        Map<String, String> requestHeaders,
        VerificationPolicy policy
    );

    /**
     * Verifies an incoming client request using the default SCITT_REQUIRED policy.
     *
     * @param clientCert the client's X.509 certificate from mTLS handshake
     * @param requestHeaders the HTTP request headers (keys must be lowercase)
     * @return a future that completes with the verification result
     * @throws NullPointerException if any parameter is null
     */
    default CompletableFuture<ClientRequestVerificationResult> verify(
            X509Certificate clientCert,
            Map<String, String> requestHeaders) {
        return verify(clientCert, requestHeaders, VerificationPolicy.SCITT_REQUIRED);
    }
}
