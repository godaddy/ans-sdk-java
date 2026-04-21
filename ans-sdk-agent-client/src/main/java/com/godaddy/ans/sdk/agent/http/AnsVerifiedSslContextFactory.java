package com.godaddy.ans.sdk.agent.http;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * Factory for creating SSLContext with ANS certificate capture.
 *
 * <p>Use this when integrating ANS verification with HTTP clients outside the SDK
 * (e.g., MCP SDK, gRPC clients, custom HTTP libraries).</p>
 *
 * <p>The SSLContext created by this factory:</p>
 * <ol>
 *   <li>Performs standard PKI validation (CA chain verification)</li>
 *   <li>Captures the server certificate for post-handshake ANS verification</li>
 *   <li>Optionally includes client certificate for mTLS</li>
 * </ol>
 *
 * <h2>Usage with MCP SDK</h2>
 * <pre>{@code
 * SslContextResult result = AnsVerifiedSslContextFactory.createWithTrustManager(keyStore, password);
 * SSLContext sslContext = result.sslContext();
 * CertificateCapturingTrustManager trustManager = result.trustManager();
 *
 * HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport
 *     .builder(serverUrl)
 *     .customizeClient(builder -> builder.sslContext(sslContext))
 *     .build();
 *
 * // After TLS handshake, retrieve captured certificate for verification
 * X509Certificate[] certs = trustManager.getInstanceCapturedCertificates(hostname);
 * }</pre>
 *
 * <h2>Usage with Standard HttpClient</h2>
 * <pre>{@code
 * SslContextResult result = AnsVerifiedSslContextFactory.createWithTrustManager(keyStore, password);
 * SSLContext sslContext = result.sslContext();
 * CertificateCapturingTrustManager trustManager = result.trustManager();
 *
 * HttpClient httpClient = HttpClient.newBuilder()
 *     .sslContext(sslContext)
 *     .sslParameters(AnsVerifiedSslContextFactory.getSecureSslParameters())
 *     .build();
 *
 * // Make request, then retrieve captured certificate
 * X509Certificate[] certs = trustManager.getInstanceCapturedCertificates(hostname);
 * }</pre>
 *
 * @see CertificateCapturingTrustManager
 */
public final class AnsVerifiedSslContextFactory {

    private AnsVerifiedSslContextFactory() {
        // No instantiation
    }

    /**
     * Result of creating an SSLContext, including access to the trust manager instance.
     *
     * @param sslContext the configured SSLContext
     * @param trustManager the capturing trust manager for instance-scoped certificate retrieval
     */
    public record SslContextResult(SSLContext sslContext, CertificateCapturingTrustManager trustManager) { }

    /**
     * Creates an SSLContext with certificate capture for ANS verification.
     *
     * <p>The returned SSLContext uses {@link CertificateCapturingTrustManager}
     * which performs standard PKI validation and captures the server certificate
     * for post-handshake verification.</p>
     *
     * @return an SSLContext configured for ANS certificate capture
     * @throws GeneralSecurityException if SSL initialization fails
     */
    public static SSLContext create() throws GeneralSecurityException {
        return create(null, null);
    }

    /**
     * Creates an SSLContext with certificate capture and mTLS client certificate.
     *
     * <p>Use this overload when connecting to servers that require client
     * certificate authentication (mTLS).</p>
     *
     * @param clientKeyStore the KeyStore containing the client certificate and private key,
     *                       or null for server-only authentication
     * @param keyPassword the password for the private key in the KeyStore,
     *                    or null if no client certificate is used
     * @return an SSLContext configured for ANS certificate capture with optional mTLS
     * @throws GeneralSecurityException if SSL initialization fails
     */
    public static SSLContext create(KeyStore clientKeyStore, char[] keyPassword)
            throws GeneralSecurityException {

        // Get the system trust manager for CA validation
        X509TrustManager systemTrustManager = getSystemTrustManager();

        // Wrap with our capturing trust manager
        CertificateCapturingTrustManager capturingTm =
                new CertificateCapturingTrustManager(systemTrustManager);

        // Set up key managers (for mTLS if client cert provided)
        KeyManager[] keyManagers = null;
        if (clientKeyStore != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(clientKeyStore, keyPassword);
            keyManagers = kmf.getKeyManagers();
        }

        // Create SSLContext - use "TLS" to allow version negotiation (supports TLS 1.2 and 1.3)
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, new TrustManager[]{capturingTm}, null);

        return sslContext;
    }

    /**
     * Creates an SSLContext with certificate capture, returning both the context
     * and the trust manager instance for instance-scoped certificate retrieval.
     *
     * @param clientKeyStore the KeyStore containing the client certificate, or null
     * @param keyPassword the password for the private key, or null
     * @return the SSLContext and trust manager instance
     * @throws GeneralSecurityException if SSL initialization fails
     */
    public static SslContextResult createWithTrustManager(KeyStore clientKeyStore, char[] keyPassword)
            throws GeneralSecurityException {

        X509TrustManager systemTrustManager = getSystemTrustManager();
        CertificateCapturingTrustManager capturingTm =
                new CertificateCapturingTrustManager(systemTrustManager);

        KeyManager[] keyManagers = null;
        if (clientKeyStore != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(clientKeyStore, keyPassword);
            keyManagers = kmf.getKeyManagers();
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, new TrustManager[]{capturingTm}, null);

        return new SslContextResult(sslContext, capturingTm);
    }

    /**
     * Gets the JVM's default X509 trust manager.
     */
    private static X509TrustManager getSystemTrustManager() throws GeneralSecurityException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }

        throw new IllegalStateException("No X509TrustManager found in default trust manager factory");
    }

    /**
     * Returns secure SSLParameters that restrict protocols to TLS 1.2 and 1.3 only.
     *
     * <p>Use this when building an HttpClient to ensure legacy protocols (TLS 1.0/1.1)
     * are not used:</p>
     *
     * <pre>{@code
     * HttpClient httpClient = HttpClient.newBuilder()
     *     .sslContext(AnsVerifiedSslContextFactory.create())
     *     .sslParameters(AnsVerifiedSslContextFactory.getSecureSslParameters())
     *     .build();
     * }</pre>
     *
     * @return SSLParameters configured for TLS 1.2 and 1.3 only
     */
    public static SSLParameters getSecureSslParameters() {
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        return params;
    }
}
