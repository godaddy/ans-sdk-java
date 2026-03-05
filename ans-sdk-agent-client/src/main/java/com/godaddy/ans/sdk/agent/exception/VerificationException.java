package com.godaddy.ans.sdk.agent.exception;

import com.godaddy.ans.sdk.agent.verification.VerificationResult;

import java.util.Objects;

/**
 * Exception thrown when verification fails outside the TLS handshake.
 *
 * <p>This exception is thrown after the TLS handshake completes if
 * post-handshake verification (DANE or Badge) fails.</p>
 */
public class VerificationException extends RuntimeException {

    private final VerificationResult result;
    private final String hostname;

    /**
     * Creates a verification exception.
     *
     * @param result the verification result that caused the failure
     * @param hostname the hostname being verified
     */
    public VerificationException(VerificationResult result, String hostname) {
        super(formatMessage(result, hostname));
        this.result = Objects.requireNonNull(result, "Result cannot be null");
        this.hostname = hostname;
    }

    /**
     * Returns the verification result that caused this exception.
     *
     * @return the verification result
     */
    public VerificationResult getResult() {
        return result;
    }

    /**
     * Returns the hostname that failed verification.
     *
     * @return the hostname
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Returns the type of verification that failed.
     *
     * @return the verification type
     */
    public VerificationResult.VerificationType getVerificationType() {
        return result.type();
    }

    private static String formatMessage(VerificationResult result, String hostname) {
        return String.format("%s verification failed for %s: %s",
            result.type(), hostname, result.reason());
    }
}
