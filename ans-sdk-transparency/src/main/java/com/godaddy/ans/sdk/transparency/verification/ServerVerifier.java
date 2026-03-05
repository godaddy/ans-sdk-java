package com.godaddy.ans.sdk.transparency.verification;

/**
 * Interface for server verification against the ANS transparency log.
 *
 * <p>This interface is implemented by both {@link BadgeVerificationService}
 * and {@link CachingBadgeVerificationService} to allow interchangeable use.</p>
 */
public interface ServerVerifier {

    /**
     * Verifies a server against the transparency log.
     *
     * @param hostname the server hostname to verify
     * @return the verification result
     */
    ServerVerificationResult verifyServer(String hostname);
}