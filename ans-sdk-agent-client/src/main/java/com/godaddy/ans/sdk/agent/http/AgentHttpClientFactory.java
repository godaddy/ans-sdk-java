package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.exception.AgentConnectionException;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Factory for creating HttpClient instances configured for agent-to-agent communication.
 *
 * <p>This factory supports two modes of operation:</p>
 * <ul>
 *   <li><b>{@link #create}</b>: Returns raw HttpClient (for backward compatibility)</li>
 *   <li><b>{@link #createVerified}</b>: Returns complete verification setup (recommended)</li>
 * </ul>
 *
 * <p>The default implementation {@link DefaultAgentHttpClientFactory} handles
 * the complex SSL setup required for ANS agent connections, with verification
 * performed <em>outside</em> the TLS handshake for better performance.</p>
 *
 * <h2>Recommended Usage</h2>
 * <pre>{@code
 * AgentHttpClientFactory factory = AgentHttpClientFactory.createDefault();
 *
 * // Create verified client (performs DANE/Badge outside handshake)
 * VerifiedClientResult result = factory.createVerified("agent.example.com",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
 *         .build(),
 *     Duration.ofSeconds(10));
 *
 * // Use the verifying client for requests
 * HttpResponse<String> response = result.ansHttpClient()
 *     .send(request, HttpResponse.BodyHandlers.ofString());
 * }</pre>
 *
 * @see DefaultAgentHttpClientFactory
 * @see ConnectOptions
 * @see AnsHttpClient
 */
public interface AgentHttpClientFactory {

    /**
     * Creates an HttpClient configured for connecting to the specified hostname.
     *
     * <p>The returned client will be configured with:</p>
     * <ul>
     *   <li>SSL context with trust managers based on verification policy</li>
     *   <li>Client certificate if mTLS is configured</li>
     *   <li>Connection timeout</li>
     * </ul>
     *
     * @param hostname the target hostname (used for SSL hostname verification)
     * @param options connection options including verification policy and client cert
     * @param connectTimeout the connection timeout
     * @return a configured HttpClient
     * @throws AgentConnectionException if client creation fails
     */
    HttpClient create(String hostname, ConnectOptions options, Duration connectTimeout)
        throws AgentConnectionException;

    /**
     * Creates a complete verified client setup for agent-to-agent communication.
     *
     * <p>This method returns a {@link VerifiedClientResult} containing:</p>
     * <ul>
     *   <li>A PKI-only HttpClient with certificate capture</li>
     *   <li>A ConnectionVerifier for DANE/Badge verification</li>
     *   <li>A AnsHttpClient that orchestrates verification outside the handshake</li>
     * </ul>
     *
     * <p>Verification is performed <em>outside</em> the TLS handshake:</p>
     * <ol>
     *   <li>Pre-verification (cached): Look up DANE/Badge expectations</li>
     *   <li>TLS handshake: PKI-only validation (fast)</li>
     *   <li>Certificate capture: Store server cert for verification</li>
     *   <li>Post-verification: Compare cert to expectations</li>
     * </ol>
     *
     * @param hostname the target hostname
     * @param options connection options including verification policy and client cert
     * @param connectTimeout the connection timeout
     * @return a complete verified client setup
     * @throws AgentConnectionException if client creation fails
     */
    VerifiedClientResult createVerified(String hostname, ConnectOptions options, Duration connectTimeout)
        throws AgentConnectionException;

    /**
     * Creates the default factory with full verification support.
     *
     * <p>This factory supports DANE and Badge verification as configured
     * in the ConnectOptions.</p>
     *
     * @return the default factory
     */
    static AgentHttpClientFactory createDefault() {
        return new DefaultAgentHttpClientFactory();
    }

    /**
     * Creates a simple factory that uses the JVM's default trust store.
     *
     * <p>This factory does not support DANE or Badge verification.
     * It's primarily useful for testing or when connecting to agents that
     * don't require ANS verification.</p>
     *
     * @return a simple factory
     */
    static AgentHttpClientFactory simple() {
        return new SimpleAgentHttpClientFactory();
    }
}