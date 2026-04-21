package com.godaddy.ans.sdk.transparency.scitt;

import java.util.Map;
import java.util.Optional;

/**
 * Provider for SCITT HTTP headers.
 *
 * <p>This interface is used by HTTP clients to:</p>
 * <ul>
 *   <li>Include SCITT artifacts in outgoing requests (for servers to verify callers)</li>
 *   <li>Extract SCITT artifacts from incoming responses (for clients to verify servers)</li>
 * </ul>
 *
 * <h2>Usage in HTTP Client</h2>
 * <pre>{@code
 * // Before sending request
 * Map<String, String> headers = scittProvider.getOutgoingHeaders();
 * request.headers().putAll(headers);
 *
 * // After receiving response
 * ScittArtifacts artifacts = scittProvider.extractArtifacts(response.headers());
 * if (artifacts.isPresent()) {
 *     ScittExpectation expectation = verifier.verify(
 *         artifacts.receipt(), artifacts.statusToken(), tlKey, raKey);
 * }
 * }</pre>
 */
public interface ScittHeaderProvider {

    /**
     * Returns headers to include in outgoing requests.
     *
     * <p>These headers contain the caller's own SCITT artifacts for
     * the server to verify the caller's identity.</p>
     *
     * @return map of header names to Base64-encoded values
     */
    Map<String, String> getOutgoingHeaders();

    /**
     * Extracts SCITT artifacts from incoming response headers.
     *
     * @param headers the response headers
     * @return the extracted artifacts, or empty if not present
     */
    Optional<ScittArtifacts> extractArtifacts(Map<String, String> headers);

    /**
     * Extracted SCITT artifacts from HTTP headers.
     *
     * @param receipt the parsed SCITT receipt (null if not present)
     * @param statusToken the parsed status token (null if not present)
     */
    record ScittArtifacts(
        ScittReceipt receipt,
        StatusToken statusToken
    ) {
        /**
         * Returns true if both receipt and status token are present.
         */
        public boolean isComplete() {
            return receipt != null && statusToken != null;
        }

        /**
         * Returns true if at least one artifact is present.
         */
        public boolean isPresent() {
            return receipt != null || statusToken != null;
        }
    }
}
