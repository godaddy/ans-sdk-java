package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.exception.AgentConnectionException;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Simple implementation of {@link AgentHttpClientFactory} using JVM defaults.
 *
 * <p>This factory creates HttpClient instances with the JVM's default SSL
 * configuration. It does not support DANE or Badge verification.</p>
 *
 * <p>Primary use cases:</p>
 * <ul>
 *   <li>Testing with mock servers</li>
 *   <li>Connecting to agents that don't require ANS verification</li>
 *   <li>Development environments with self-signed certificates in trust store</li>
 * </ul>
 *
 * <p><strong>Note:</strong> This factory ignores the verification policy in
 * ConnectOptions. For production use with proper verification, use
 * {@link DefaultAgentHttpClientFactory} instead.</p>
 */
public class SimpleAgentHttpClientFactory implements AgentHttpClientFactory {

    @Override
    public HttpClient create(String hostname, ConnectOptions options, Duration connectTimeout)
            throws AgentConnectionException {
        return createVerified(hostname, options, connectTimeout).ansHttpClient().getDelegate();
    }

    @Override
    public VerifiedClientResult createVerified(String hostname, ConnectOptions options, Duration connectTimeout)
            throws AgentConnectionException {
        try {
            HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .build();

            // Create verifying client with PKI_ONLY policy (no verification)
            AnsHttpClient verifyingClient = AnsHttpClient.builder()
                .delegate(httpClient)
                .connectionVerifier(NoOpConnectionVerifier.INSTANCE)
                .verificationPolicy(VerificationPolicy.PKI_ONLY)
                .build();

            return new VerifiedClientResult(NoOpConnectionVerifier.INSTANCE, verifyingClient);

        } catch (Exception e) {
            throw new AgentConnectionException(
                "Failed to create HTTP client: " + e.getMessage(), e, hostname);
        }
    }
}