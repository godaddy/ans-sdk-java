package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.exception.AgentConnectionException;
import com.godaddy.ans.sdk.agent.verification.BadgeVerifier;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DaneVerifier;
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
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

    // Shared cached verification service - reduces blocking on repeated connections
    private volatile CachingBadgeVerificationService cachedVerificationService;

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
            // Create HttpClient with PKI-only SSL (certificate capture)
            SSLContext sslContext = createPkiOnlySslContext(options);

            // Restrict to TLS 1.2 and 1.3 only (no TLS 1.0/1.1)
            SSLParameters sslParameters = new SSLParameters();
            sslParameters.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

            HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(sslParameters)
                .connectTimeout(connectTimeout)
                .build();

            // Create ConnectionVerifier based on policy
            ConnectionVerifier verifier = createConnectionVerifier(options);

            // Create AnsHttpClient wrapper
            AnsHttpClient verifyingClient = AnsHttpClient.builder()
                .delegate(httpClient)
                .connectionVerifier(verifier)
                .verificationPolicy(options.getVerificationPolicy())
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
     * Creates an SSL context with PKI-only validation and certificate capture.
     *
     * <p>The returned SSLContext uses {@link CertificateCapturingTrustManager}
     * which performs standard PKI validation and captures the server certificate
     * for post-handshake verification.</p>
     */
    private SSLContext createPkiOnlySslContext(ConnectOptions options) throws Exception {
        KeyManager[] keyManagers = null;

        // Load client certificate if provided (for mTLS)
        if (options.hasClientCertificate()) {
            keyManagers = loadKeyManagers(options);
        }

        // Use CertificateCapturingTrustManager for PKI-only + certificate capture
        X509TrustManager systemTm = getSystemTrustManager();
        CertificateCapturingTrustManager capturingTm = new CertificateCapturingTrustManager(systemTm);
        TrustManager[] trustManagers = new TrustManager[]{capturingTm};

        // Use "TLS" to allow version negotiation (supports TLS 1.2 and 1.3)
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);

        return sslContext;
    }

    /**
     * Creates a ConnectionVerifier based on the verification policy.
     *
     * <p>This creates verifiers for DANE and Badge based on which
     * verification modes are enabled in the policy.</p>
     */
    private ConnectionVerifier createConnectionVerifier(ConnectOptions options) {
        VerificationPolicy policy = options.getVerificationPolicy();
        DefaultConnectionVerifier.Builder builder = DefaultConnectionVerifier.builder();

        // Add DANE verifier if not disabled
        if (policy.daneMode() != VerificationMode.DISABLED) {
            LOGGER.debug("DANE verification enabled (mode={})", policy.daneMode());
            builder.daneVerifier(new DaneVerifier(daneVerifier));
        }

        // Add Badge verifier if not disabled
        if (policy.badgeMode() != VerificationMode.DISABLED) {
            ServerVerifier verificationService = getOrCreateVerificationService(options);
            LOGGER.debug("Badge verification enabled (mode={}, cached=true)", policy.badgeMode());
            builder.badgeVerifier(new BadgeVerifier(verificationService));
        }

        return builder.build();
    }

    /**
     * Gets or creates a verification service for identity verification.
     *
     * <p>If an explicit TransparencyClient is provided in options, a fresh service is created
     * for that client (not cached). This allows callers to use different transparency endpoints
     * (e.g., production vs OTE) for different connections.</p>
     *
     * <p>If no TransparencyClient is provided, a shared cached service is used which reduces
     * blocking during TLS handshakes for repeated connections to the same hosts.</p>
     */
    private ServerVerifier getOrCreateVerificationService(ConnectOptions options) {
        // If explicit TransparencyClient provided, create a fresh service (don't cache)
        TransparencyClient explicitClient = options.getTransparencyClient();
        if (explicitClient != null) {
            LOGGER.debug("Using explicit TransparencyClient - creating fresh verification service");
            BadgeVerificationService delegate = BadgeVerificationService.builder()
                .transparencyClient(explicitClient)
                .build();
            // Wrap in caching for this client instance
            return CachingBadgeVerificationService.builder()
                .delegate(delegate)
                .build();
        }

        // No explicit client - use shared cached default service
        if (cachedVerificationService == null) {
            synchronized (this) {
                if (cachedVerificationService == null) {
                    TransparencyClient defaultClient = TransparencyClient.create();

                    BadgeVerificationService delegate = BadgeVerificationService.builder()
                        .transparencyClient(defaultClient)
                        .build();

                    cachedVerificationService = CachingBadgeVerificationService.builder()
                        .delegate(delegate)
                        .build();

                    LOGGER.debug("Created cached default verification service"
                            + " (15 min positive TTL, 5 min negative TTL)");
                }
            }
        }
        return cachedVerificationService;
    }

    /**
     * Gets the JVM's default trust manager.
     */
    private X509TrustManager getSystemTrustManager() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }

        throw new IllegalStateException("No X509TrustManager found");
    }

    /**
     * Loads key managers for client certificate (mTLS).
     */
    private KeyManager[] loadKeyManagers(ConnectOptions options) throws Exception {
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

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, DEFAULT_KEY_PASSWORD.toCharArray());

        return kmf.getKeyManagers();
    }
}