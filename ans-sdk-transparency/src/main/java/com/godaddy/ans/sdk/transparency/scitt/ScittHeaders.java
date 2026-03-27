package com.godaddy.ans.sdk.transparency.scitt;

/**
 * HTTP header constants for SCITT artifact delivery.
 *
 * <p>SCITT artifacts (receipts and status tokens) are delivered via HTTP headers
 * to eliminate live Transparency Log queries during connection establishment.</p>
 */
public final class ScittHeaders {

    /**
     * HTTP header for SCITT receipt (Base64-encoded COSE_Sign1).
     *
     * <p>Contains the cryptographic proof that the agent's registration
     * was included in the Transparency Log.</p>
     */
    public static final String SCITT_RECEIPT_HEADER = "x-scitt-receipt";

    /**
     * HTTP header for ANS status token (Base64-encoded COSE_Sign1).
     *
     * <p>Contains a time-bounded assertion of the agent's current status,
     * including valid certificate fingerprints.</p>
     */
    public static final String STATUS_TOKEN_HEADER = "x-ans-status-token";

    private ScittHeaders() {
        // Constants class
    }
}
