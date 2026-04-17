package com.godaddy.ans.sdk.agent;

import com.godaddy.ans.sdk.agent.http.CapturedCertificateProvider;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Represents a connection to an ANS-verified server.
 *
 * <p>Created by {@link AnsVerifiedClient#connect(String)}, this class holds
 * pre-verification results and provides post-verification after TLS handshake.</p>
 *
 * <p>Based on the policy, verification may include DANE, Badge, and/or SCITT.
 * The {@link #verifyServer()} method combines all results according to the policy.</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * AnsVerifiedClient ansClient = AnsVerifiedClient.builder()
 *     .agentId("my-agent-id")
 *     .keyStorePath("/path/to/client.p12", "password")
 *     .build();
 *
 * try (AnsConnection connection = ansClient.connect(serverUrl)) {
 *     // Use MCP SDK to establish connection...
 *     mcpClient.initialize();
 *
 *     // Post-verify the server certificate
 *     VerificationResult result = connection.verifyServer();
 *     if (!result.isSuccess()) {
 *         throw new SecurityException("Verification failed: " + result.reason());
 *     }
 * }
 * }</pre>
 */
public class AnsConnection implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnsConnection.class);

    private final String hostname;
    private final PreVerificationResult preResult;
    private final ConnectionVerifier verifier;
    private final VerificationPolicy policy;
    private final CapturedCertificateProvider certProvider;

    /**
     * Creates a new AnsConnection.
     *
     * <p>This constructor is package-private; use {@link AnsVerifiedClient#connect(String)}
     * to create connections.</p>
     *
     * @param hostname the hostname being connected to
     * @param preResult the pre-verification result
     * @param verifier the connection verifier
     * @param policy the verification policy
     * @param certProvider the provider for captured server certificates
     */
    AnsConnection(String hostname, PreVerificationResult preResult,
                  ConnectionVerifier verifier, VerificationPolicy policy,
                  CapturedCertificateProvider certProvider) {
        this.hostname = hostname;
        this.preResult = preResult;
        this.verifier = verifier;
        this.policy = policy;
        this.certProvider = certProvider;
    }

    /**
     * Returns the hostname being connected to.
     *
     * @return the hostname
     */
    public String hostname() {
        return hostname;
    }

    /**
     * Returns the combined pre-verification result.
     *
     * @return the pre-verification result
     */
    public PreVerificationResult preVerifyResult() {
        return preResult;
    }

    /**
     * Returns whether SCITT artifacts were present in server response.
     *
     * @return true if SCITT artifacts are available
     */
    public boolean hasScittArtifacts() {
        return preResult.hasScittExpectation();
    }

    /**
     * Returns whether Badge registration was found.
     *
     * @return true if badge fingerprints are available
     */
    public boolean hasBadgeRegistration() {
        return preResult.hasBadgeExpectation();
    }

    /**
     * Returns whether DANE/TLSA records were found.
     *
     * @return true if DANE expectations are available
     */
    public boolean hasDaneRecords() {
        return preResult.hasDaneExpectation();
    }

    /**
     * Verifies the server certificate after TLS handshake.
     *
     * <p>Runs all enabled post-verifications (DANE, Badge, SCITT) and combines
     * results according to the policy. Returns SUCCESS if all REQUIRED verifications
     * pass, logs warnings for ADVISORY failures.</p>
     *
     * @return the combined verification result
     * @throws SecurityException if no server certificate was captured
     */
    public VerificationResult verifyServer() {
        X509Certificate[] certs = certProvider.getCapturedCertificates(hostname);
        if (certs == null || certs.length == 0) {
            throw new SecurityException("No server certificate captured for " + hostname);
        }
        return verifyServer(certs[0]);
    }

    /**
     * Verifies using an explicitly provided certificate.
     *
     * @param serverCert the server's certificate
     * @return the combined verification result
     */
    public VerificationResult verifyServer(X509Certificate serverCert) {
        LOGGER.debug("Post-verifying server certificate for {}", hostname);

        List<VerificationResult> results = verifier.postVerify(hostname, serverCert, preResult);
        VerificationResult combined = verifier.combine(results, policy);

        LOGGER.debug("Combined verification result for {}: {} ({})",
            hostname, combined.status(), combined.type());

        return combined;
    }

    /**
     * Returns individual verification results without combining.
     *
     * <p>Useful for debugging or detailed logging.</p>
     *
     * @param serverCert the server's certificate
     * @return list of individual verification results
     */
    public List<VerificationResult> verifyServerDetailed(X509Certificate serverCert) {
        return verifier.postVerify(hostname, serverCert, preResult);
    }

    /**
     * Returns individual verification results without combining, using captured certificate.
     *
     * @return list of individual verification results
     * @throws SecurityException if no server certificate was captured
     */
    public List<VerificationResult> verifyServerDetailed() {
        X509Certificate[] certs = certProvider.getCapturedCertificates(hostname);
        if (certs == null || certs.length == 0) {
            throw new SecurityException("No server certificate captured for " + hostname);
        }
        return verifyServerDetailed(certs[0]);
    }

    @Override
    public void close() {
        certProvider.clearCapturedCertificates(hostname);
        LOGGER.debug("Cleared captured certificates for {}", hostname);
    }
}
