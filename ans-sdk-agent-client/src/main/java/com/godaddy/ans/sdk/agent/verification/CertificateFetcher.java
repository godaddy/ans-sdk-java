package com.godaddy.ans.sdk.agent.verification;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * Interface for fetching server TLS certificates.
 *
 * <p>This interface allows for dependency injection of certificate fetching,
 * making it easier to test DANE verification code without making real TLS connections.</p>
 */
@FunctionalInterface
public interface CertificateFetcher {

    /**
     * Fetches the server's TLS certificate.
     *
     * @param hostname the server hostname
     * @param port the server port
     * @return the server's X.509 certificate
     * @throws IOException if the connection fails or no certificate is received
     */
    X509Certificate getCertificate(String hostname, int port) throws IOException;

    /**
     * Returns the default fetcher that makes real TLS connections.
     *
     * @return the default certificate fetcher
     */
    static CertificateFetcher defaultFetcher() {
        return DefaultCertificateFetcher.INSTANCE;
    }
}
