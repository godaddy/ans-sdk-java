package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;

import java.util.Objects;

/**
 * Result of creating a verified HTTP client setup.
 *
 * <p>This record contains all the components needed for agent communication
 * with verification outside the TLS handshake:</p>
 * <ul>
 *   <li><b>verifier</b>: ConnectionVerifier for pre/post verification</li>
 *   <li><b>ansHttpClient</b>: Wrapper that orchestrates verification</li>
 * </ul>
 *  @param verifier the connection verifier for DANE/Badge verification
 *
 * @param ansHttpClient the wrapper client that performs verification
 */
public record VerifiedClientResult(
        ConnectionVerifier verifier,
        AnsHttpClient ansHttpClient
) {

    public VerifiedClientResult {
        Objects.requireNonNull(verifier, "ConnectionVerifier cannot be null");
        Objects.requireNonNull(ansHttpClient, "AnsHttpClient cannot be null");
    }
}
