package com.godaddy.ans.sdk.transparency.scitt;

/**
 * Result of SCITT pre-verification from HTTP response headers.
 *
 * <p>This record captures the outcome of extracting and verifying SCITT artifacts
 * (receipts and status tokens) from HTTP headers before post-verification of
 * the TLS certificate.</p>
 *
 * @param expectation the SCITT expectation containing valid fingerprints and status
 * @param receipt the parsed SCITT receipt (may be null if not present or parsing failed)
 * @param statusToken the parsed status token (may be null if not present or parsing failed)
 * @param isPresent true if SCITT headers were present in the response
 */
public record ScittPreVerifyResult(
    ScittExpectation expectation,
    ScittReceipt receipt,
    StatusToken statusToken,
    boolean isPresent
) {

    /**
     * Creates a result indicating SCITT headers were not present in the response.
     *
     * @return a result with isPresent=false and a NOT_PRESENT expectation
     */
    public static ScittPreVerifyResult notPresent() {
        return new ScittPreVerifyResult(ScittExpectation.notPresent(), null, null, false);
    }

    /**
     * Creates a result indicating a parse error occurred.
     *
     * @param errorMessage the error message
     * @return a result with isPresent=true but a PARSE_ERROR expectation
     */
    public static ScittPreVerifyResult parseError(String errorMessage) {
        return new ScittPreVerifyResult(
            ScittExpectation.parseError(errorMessage),
            null, null, true);
    }

    /**
     * Creates a successful pre-verification result.
     *
     * @param expectation the verified expectation
     * @param receipt the parsed receipt
     * @param statusToken the parsed status token
     * @return a result with isPresent=true and the verified expectation
     */
    public static ScittPreVerifyResult verified(
            ScittExpectation expectation,
            ScittReceipt receipt,
            StatusToken statusToken) {
        return new ScittPreVerifyResult(expectation, receipt, statusToken, true);
    }
}
