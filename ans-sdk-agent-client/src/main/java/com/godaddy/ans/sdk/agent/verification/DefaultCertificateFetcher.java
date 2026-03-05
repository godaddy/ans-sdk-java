package com.godaddy.ans.sdk.agent.verification;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Default implementation of {@link CertificateFetcher} that makes real TLS connections.
 */
public final class DefaultCertificateFetcher implements CertificateFetcher {

    /**
     * Singleton instance.
     */
    public static final DefaultCertificateFetcher INSTANCE = new DefaultCertificateFetcher();

    private static final int DEFAULT_TIMEOUT = 10000;

    private DefaultCertificateFetcher() {
        // Singleton
    }

    @Override
    public X509Certificate getCertificate(String hostname, int port) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, port)) {
            socket.setSoTimeout(DEFAULT_TIMEOUT);
            socket.startHandshake();

            Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs == null || certs.length == 0) {
                throw new IOException("No certificates received from server");
            }

            return (X509Certificate) certs[0];
        }
    }
}
