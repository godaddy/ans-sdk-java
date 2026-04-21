package com.godaddy.ans.sdk.agent.http;

import java.security.cert.X509Certificate;

/**
 * Provides captured server certificates for post-handshake verification.
 *
 * <p>Abstracts the static coupling to {@link CertificateCapturingTrustManager},
 * enabling unit testing of {@link com.godaddy.ans.sdk.agent.AnsConnection}
 * without full TLS infrastructure.</p>
 */
@FunctionalInterface
public interface CapturedCertificateProvider {

    /**
     * Returns the captured certificate chain for the specified hostname.
     *
     * @param hostname the hostname to get certificates for
     * @return the captured certificate chain, or null if unavailable
     */
    X509Certificate[] getCapturedCertificates(String hostname);

    /**
     * Clears the captured certificates for the specified hostname.
     *
     * <p>Call this after processing the certificates to prevent memory leaks.
     * The default implementation is a no-op, preserving backward compatibility
     * for lambda and method-reference callers.</p>
     *
     * @param hostname the hostname to clear certificates for
     */
    default void clearCapturedCertificates(String hostname) { }
}
