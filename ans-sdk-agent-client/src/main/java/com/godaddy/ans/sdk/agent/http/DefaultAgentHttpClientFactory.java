package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.exception.AgentConnectionException;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DaneConfig;
import com.godaddy.ans.sdk.agent.verification.DaneTlsaVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.godaddy.ans.sdk.crypto.CertificateUtils;
import com.godaddy.ans.sdk.crypto.KeyPairManager;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.verification.BadgeVerificationService;
import com.godaddy.ans.sdk.transparency.verification.CachingBadgeVerificationService;
import com.godaddy.ans.sdk.transparency.verification.ServerVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Default implementation of {@link AgentHttpClientFactory} with full verification support.
 *
 * <p>This factory creates HttpClient instances with verification performed
 * <em>outside</em> the TLS handshake for better performance:</p>
 * <ul>
 *   <li><b>DANE verification</b>: DNS-based TLSA record verification</li>
 *   <li><b>Badge verification</b>: ANS transparency log verification</li>
 *   <li><b>mTLS</b>: Client certificate authentication</li>
 * </ul>
 *
 * <p>The verification flow is:</p>
 * <ol>
 *   <li><b>Pre-verify</b>: Look up DANE/Badge expectations (cached)</li>
 *   <li><b>TLS handshake</b>: PKI-only validation (fast)</li>
 *   <li><b>Capture cert</b>: Store server certificate via CertificateCapturingTrustManager</li>
 *   <li><b>Post-verify</b>: Compare captured cert to expectations</li>
 * </ol>
 */
public class DefaultAgentHttpClientFactory implements AgentHttpClientFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultAgentHttpClientFactory.class);
    // Acceptable for transient in-memory keystore
    private static final String DEFAULT_KEY_PASSWORD = "changeit";

    private final DaneTlsaVerifier daneVerifier;

    /**
     * Creates a factory with the default DANE verifier.
     */
    public DefaultAgentHttpClientFactory() {
        this(new DefaultDaneTlsaVerifier(DaneConfig.defaults()));
    }

    /**
     * Creates a factory with a custom DANE verifier.
     *
     * @param daneVerifier the DANE verifier to use
     */
    public DefaultAgentHttpClientFactory(DaneTlsaVerifier daneVerifier) {
        this.daneVerifier = Objects.requireNonNull(daneVerifier, "DANE verifier cannot be null");
    }

    @Override
    public HttpClient create(String hostname, ConnectOptions options, Duration connectTimeout)
            throws AgentConnectionException {
        // Delegate to createVerified and return just the underlying HttpClient
        return createVerified(hostname, options, connectTimeout).ansHttpClient().getDelegate();
    }

    @Override
    public VerifiedClientResult createVerified(String hostname, ConnectOptions options, Duration connectTimeout)
            throws AgentConnectionException {
        Objects.requireNonNull(hostname, "Hostname cannot be null");
        Objects.requireNonNull(options, "Options cannot be null");
        Objects.requireNonNull(connectTimeout, "Connect timeout cannot be null");

        try {
            // Build client keystore from ConnectOptions (for mTLS)
            KeyStore clientKeyStore = null;
            if (options.hasClientCertificate()) {
                clientKeyStore = buildClientKeyStore(options);
            }

            // Create SSLContext with certificate capture via shared factory
            AnsVerifiedSslContextFactory.SslContextResult sslResult =
                AnsVerifiedSslContextFactory.createWithTrustManager(clientKeyStore,
                    DEFAULT_KEY_PASSWORD.toCharArray());

            HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslResult.sslContext())
                .sslParameters(AnsVerifiedSslContextFactory.getSecureSslParameters())
                .connectTimeout(connectTimeout)
                .build();

            // Create ConnectionVerifier based on policy (with SCITT support)
            ConnectionVerifier verifier = createConnectionVerifier(options);

            // Create AnsHttpClient wrapper
            AnsHttpClient verifyingClient = AnsHttpClient.builder()
                .delegate(httpClient)
                .connectionVerifier(verifier)
                .verificationPolicy(options.getVerificationPolicy())
                .certProvider(sslResult.trustManager())
                .build();

            LOGGER.debug("Created verified client for {} with policy: {}",
                hostname, options.getVerificationPolicy());

            return new VerifiedClientResult(verifier, verifyingClient);

        } catch (AgentConnectionException e) {
            throw e;
        } catch (Exception e) {
            throw new AgentConnectionException(
                "Failed to create verified HTTP client: " + e.getMessage(), e, hostname);
        }
    }

    /**
     * Creates a ConnectionVerifier based on the verification policy.
     *
     * <p>Delegates to {@link DefaultConnectionVerifier#fromPolicy} with the factory's
     * DANE verifier and an optional badge service override for shared caching.</p>
     */
    private ConnectionVerifier createConnectionVerifier(ConnectOptions options) {
        VerificationPolicy policy = options.getVerificationPolicy();
        TransparencyClient transparencyClient = options.getTransparencyClient();
        ServerVerifier badgeService = getOrCreateVerificationService(options, policy);

        return DefaultConnectionVerifier.fromPolicy(
            policy, transparencyClient, daneVerifier, badgeService);
    }

    /**
     * Gets or creates a badge verification service.
     *
     * <p>Returns null if badge verification is disabled. Requires an explicit
     * TransparencyClient in ConnectOptions when badge verification is enabled.</p>
     *
     * @throws IllegalStateException if badge is enabled but no TransparencyClient provided
     */
    private ServerVerifier getOrCreateVerificationService(ConnectOptions options,
                                                           VerificationPolicy policy) {
        if (policy.badgeMode() == VerificationMode.DISABLED) {
            return null;
        }

        // If explicit TransparencyClient provided, create a fresh service (don't cache)
        TransparencyClient explicitClient = options.getTransparencyClient();
        if (explicitClient != null) {
            LOGGER.debug("Using explicit TransparencyClient - creating fresh verification service");
            BadgeVerificationService delegate = BadgeVerificationService.builder()
                .transparencyClient(explicitClient)
                .build();
            return CachingBadgeVerificationService.builder()
                .delegate(delegate)
                .build();
        }

        // No explicit client - badge verification requires a TransparencyClient
        throw new IllegalStateException(
            "Badge verification is enabled but no TransparencyClient was provided in "
            + "ConnectOptions. Use ConnectOptions.builder().transparencyClient("
            + "TransparencyClient.builder().baseUrl(...).build()) to specify the "
            + "transparency log environment.");
    }

    /**
     * Builds a client keystore from ConnectOptions for mTLS.
     */
    private KeyStore buildClientKeyStore(ConnectOptions options) throws Exception {
        Certificate[] certChain;
        PrivateKey key;

        if (options.getClientCert() != null && options.getClientKey() != null) {
            // Use pre-loaded certificate (single cert only)
            certChain = new Certificate[]{options.getClientCert()};
            key = options.getClientKey();
        } else {
            // Load from files - include full certificate chain for proper mTLS
            String certPem = Files.readString(options.getClientCertPath());
            // Handle escaped newlines (common in some PEM files)
            certPem = certPem.replace("\\n", "\n");
            List<X509Certificate> chain = CertificateUtils.parseCertificateChain(certPem);
            // Pass the full chain (leaf + intermediates) for mTLS
            certChain = chain.toArray(new Certificate[0]);

            KeyPairManager keyManager = new KeyPairManager();
            KeyPair keyPair = keyManager.loadKeyPairFromPem(
                options.getClientKeyPath(),
                options.getClientKeyPassword()
            );
            key = keyPair.getPrivate();
        }

        // Create key store with client credentials (full chain if available)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", key, DEFAULT_KEY_PASSWORD.toCharArray(), certChain);

        return keyStore;
    }
}