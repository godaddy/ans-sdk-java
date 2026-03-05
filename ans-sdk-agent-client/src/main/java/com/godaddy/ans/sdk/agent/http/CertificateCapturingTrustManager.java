package com.godaddy.ans.sdk.agent.http;

import com.godaddy.ans.sdk.crypto.CertificateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A TrustManager that captures server certificates during TLS handshake.
 *
 * <p>This TrustManager performs only standard PKI validation (delegating to the
 * underlying trust manager), while capturing the server certificate chain for
 * post-handshake verification.</p>
 *
 * <p>Certificates are stored in a {@link ConcurrentHashMap} keyed by a composite
 * key of hostname and session identifier, ensuring thread-safety for concurrent
 * requests to the same host.</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Create capturing trust manager
 * X509TrustManager systemTm = getSystemTrustManager();
 * CertificateCapturingTrustManager capturingTm = new CertificateCapturingTrustManager(systemTm);
 *
 * // Use in SSLContext
 * SSLContext sslContext = SSLContext.getInstance("TLS");
 * sslContext.init(keyManagers, new TrustManager[]{capturingTm}, null);
 *
 * // After TLS handshake
 * X509Certificate[] certs = CertificateCapturingTrustManager.getCapturedCertificates("example.com");
 * // ... perform DANE/Badge verification with certs[0] ...
 * CertificateCapturingTrustManager.clearCapturedCertificates("example.com");
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This implementation is thread-safe. Certificates are stored in a shared
 * ConcurrentHashMap keyed by hostname + session ID. Always call {@link #clearCapturedCertificates(String)}
 * after retrieving the certificates to prevent memory leaks.</p>
 */
public class CertificateCapturingTrustManager extends X509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateCapturingTrustManager.class);

    /**
     * Shared storage for captured certificates, keyed by composite key (hostname:sessionId).
     * This is thread-safe and works across the TLS worker threads and calling threads.
     */
    private static final ConcurrentMap<String, X509Certificate[]> CAPTURED_CERTIFICATES = new ConcurrentHashMap<>();

    private final X509TrustManager delegate;

    /**
     * Creates a certificate-capturing trust manager.
     *
     * @param delegate the underlying trust manager for PKI validation
     */
    public CertificateCapturingTrustManager(X509TrustManager delegate) {
        this.delegate = Objects.requireNonNull(delegate, "Delegate trust manager cannot be null");
    }

    /**
     * Returns the captured certificate chain for the specified hostname.
     *
     * <p>This method finds and removes the first certificate entry matching the hostname,
     * supporting concurrent requests to the same host. Each call returns certificates
     * from a single request.</p>
     *
     * @param hostname the hostname to get certificates for
     * @return the captured certificate chain, or null if no handshake occurred for this host
     */
    public static X509Certificate[] getCapturedCertificates(String hostname) {
        // Find first entry matching hostname prefix and atomically remove it
        String prefix = hostname + ":";
        for (Map.Entry<String, X509Certificate[]> entry : CAPTURED_CERTIFICATES.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(prefix) || key.equals(hostname)) {
                X509Certificate[] certs = CAPTURED_CERTIFICATES.remove(key);
                if (certs != null) {
                    LOGGER.debug("Retrieved and removed certificates for key: {}", key);
                    return certs.clone();
                }
            }
        }
        // Fall back to exact hostname match for backward compatibility
        X509Certificate[] certificates = CAPTURED_CERTIFICATES.remove(hostname);
        return certificates != null ? certificates.clone() : null;
    }

    /**
     * Returns the captured certificate chain for the specified hostname and session ID.
     *
     * @param hostname the hostname to get certificates for
     * @param sessionId the SSL session ID (hex encoded)
     * @return the captured certificate chain, or null if no handshake occurred
     */
    public static X509Certificate[] getCapturedCertificates(String hostname, String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            return getCapturedCertificates(hostname);
        }
        String key = compositeKey(hostname, sessionId);
        X509Certificate[] certificates = CAPTURED_CERTIFICATES.remove(key);
        if (certificates != null) {
            LOGGER.debug("Retrieved and removed certificates for key: {}", key);
            return certificates.clone();
        }
        return null;
    }

    /**
     * Clears the captured certificates for the specified hostname.
     *
     * <p>Call this after processing the certificates to prevent memory leaks.
     * This clears all entries matching the hostname (all session IDs).</p>
     *
     * @param hostname the hostname to clear certificates for
     */
    public static void clearCapturedCertificates(String hostname) {
        String prefix = hostname + ":";
        Iterator<String> iterator = CAPTURED_CERTIFICATES.keySet().iterator();
        int cleared = 0;
        while (iterator.hasNext()) {
            String key = iterator.next();
            if (key.startsWith(prefix) || key.equals(hostname)) {
                iterator.remove();
                cleared++;
            }
        }
        if (cleared > 0) {
            LOGGER.debug("Cleared {} captured certificate(s) for {}", cleared, hostname);
        }
    }

    /**
     * Clears the captured certificates for the specified hostname and session ID.
     *
     * @param hostname the hostname to clear certificates for
     * @param sessionId the SSL session ID (hex encoded)
     */
    public static void clearCapturedCertificates(String hostname, String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            clearCapturedCertificates(hostname);
            return;
        }
        String key = compositeKey(hostname, sessionId);
        if (CAPTURED_CERTIFICATES.remove(key) != null) {
            LOGGER.debug("Cleared captured certificates for key: {}", key);
        }
    }

    /**
     * Clears all captured certificates.
     *
     * <p>Call this after processing the certificates to prevent memory leaks.</p>
     */
    public static void clearCapturedCertificates() {
        CAPTURED_CERTIFICATES.clear();
    }

    /**
     * Creates a composite key from hostname and session ID.
     */
    private static String compositeKey(String hostname, String sessionId) {
        return hostname + ":" + sessionId;
    }

    /**
     * Extracts session ID from an SSLEngine, falling back to identity hash code if unavailable.
     */
    private static String extractSessionId(SSLEngine engine) {
        if (engine == null) {
            return "";
        }
        try {
            SSLSession session = engine.getSession();
            if (session != null) {
                byte[] sessionId = session.getId();
                if (sessionId != null && sessionId.length > 0) {
                    return HexFormat.of().formatHex(sessionId);
                }
            }
        } catch (Exception e) {
            LOGGER.trace("Could not extract session ID from SSLEngine", e);
        }
        // Fall back to identity hash code for uniqueness
        return "engine-" + System.identityHashCode(engine);
    }

    /**
     * Extracts a unique identifier from a Socket for use as session ID.
     */
    private static String extractSessionId(Socket socket) {
        if (socket == null) {
            return "";
        }
        // Use local port as unique identifier (each connection has unique local port)
        return "socket-" + socket.getLocalPort();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // Perform PKI validation only
        delegate.checkServerTrusted(chain, authType);

        // Can't capture by hostname without SSLEngine - use certificate's CN
        captureCertificatesBySubject(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        // Perform PKI validation only
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, socket);
        } else {
            delegate.checkServerTrusted(chain, authType);
        }

        // Get hostname from socket
        String hostname = null;
        if (socket.getRemoteSocketAddress() instanceof InetSocketAddress addr) {
            hostname = addr.getHostString();
        }
        String sessionId = extractSessionId(socket);
        captureCertificates(hostname, sessionId, chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        // Perform PKI validation only
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate).checkServerTrusted(chain, authType, engine);
        } else {
            delegate.checkServerTrusted(chain, authType);
        }

        // Get hostname and session ID from SSLEngine
        String hostname = engine.getPeerHost();
        String sessionId = extractSessionId(engine);
        captureCertificates(hostname, sessionId, chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate).checkClientTrusted(chain, authType, socket);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate).checkClientTrusted(chain, authType, engine);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    /**
     * Captures the certificate chain for the specified hostname and session ID.
     */
    private void captureCertificates(String hostname, String sessionId, X509Certificate[] chain) {
        if (chain != null && chain.length > 0) {
            if (hostname != null) {
                String key = (sessionId != null && !sessionId.isEmpty())
                    ? compositeKey(hostname, sessionId)
                    : hostname;
                CAPTURED_CERTIFICATES.put(key, chain.clone());
                LOGGER.debug("Captured {} certificate(s) for key: {}", chain.length, key);
            } else {
                // Fallback to subject-based capture
                captureCertificatesBySubject(chain);
            }
        }
    }

    /**
     * Captures certificates using the certificate's FQDN as key.
     * Prefers DNS SANs, falls back to CN. Used when hostname is not available.
     */
    private void captureCertificatesBySubject(X509Certificate[] chain) {
        if (chain != null && chain.length > 0) {
            // Use CertificateUtils.extractFqdn which prefers SANs and uses robust CN parsing
            CertificateUtils.extractFqdn(chain[0]).ifPresentOrElse(
                fqdn -> {
                    CAPTURED_CERTIFICATES.put(fqdn, chain.clone());
                    LOGGER.debug("Captured {} certificate(s) by FQDN: {}", chain.length, fqdn);
                },
                () -> LOGGER.warn("Could not determine hostname for certificate capture")
            );
        }
    }
}
