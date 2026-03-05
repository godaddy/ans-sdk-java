package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * A no-op implementation of {@link ConnectionVerifier} that performs no verification.
 *
 * <p>This is useful for:</p>
 * <ul>
 *   <li>Testing with mock servers</li>
 *   <li>PKI-only verification scenarios</li>
 *   <li>Development environments</li>
 * </ul>
 *
 * <p>All methods return successful/empty results without performing any actual verification.</p>
 */
public final class NoOpConnectionVerifier implements ConnectionVerifier {

    /** Singleton instance for convenience. */
    public static final NoOpConnectionVerifier INSTANCE = new NoOpConnectionVerifier();

    /**
     * Creates a new no-op connection verifier.
     */
    public NoOpConnectionVerifier() {
    }

    @Override
    public CompletableFuture<PreVerificationResult> preVerify(String hostname, int port) {
        return CompletableFuture.completedFuture(
            PreVerificationResult.builder(hostname, port).build());
    }

    @Override
    public List<VerificationResult> postVerify(String hostname, X509Certificate serverCert,
                                                PreVerificationResult preResult) {
        return List.of();
    }

    @Override
    public VerificationResult combine(List<VerificationResult> results, VerificationPolicy policy) {
        return VerificationResult.skipped("No additional verification performed (PKI only)");
    }
}