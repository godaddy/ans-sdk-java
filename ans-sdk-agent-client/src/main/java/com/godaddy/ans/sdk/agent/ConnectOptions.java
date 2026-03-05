package com.godaddy.ans.sdk.agent;

import com.godaddy.ans.sdk.agent.http.auth.HttpAuthHeadersProvider;
import com.godaddy.ans.sdk.transparency.TransparencyClient;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Configuration options for agent connections.
 *
 * <p>Use the builder to configure verification policy, mTLS client certificates, and
 * other connection options.</p>
 *
 * <h2>Verification Policy</h2>
 *
 * <p>Use {@link VerificationPolicy} to configure which verification methods to use:</p>
 *
 * <h3>Badge Verification (Recommended Default)</h3>
 * <pre>{@code
 * AgentConnection conn = client.connect("target.example.com",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
 *         .build());
 * }</pre>
 *
 * <h3>DANE + Badge Verification</h3>
 * <pre>{@code
 * AgentConnection conn = client.connect("target.example.com",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
 *         .build());
 * }</pre>
 *
 * <h3>Custom Verification</h3>
 * <pre>{@code
 * AgentConnection conn = client.connect("target.example.com",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.custom()
 *             .dane(VerificationMode.ADVISORY)
 *             .badge(VerificationMode.REQUIRED)
 *             .build())
 *         .build());
 * }</pre>
 *
 * <h3>With mTLS Client Certificate</h3>
 * <pre>{@code
 * AgentConnection conn = client.connect("target.example.com",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
 *         .clientCertPath(Path.of("/path/to/cert.pem"))
 *         .clientKeyPath(Path.of("/path/to/key.pem"))
 *         .build());
 * }</pre>
 *
 * @see VerificationPolicy
 * @see VerificationMode
 * @see AnsClient#connect(String, ConnectOptions)
 */
public final class ConnectOptions {

    private final VerificationPolicy verificationPolicy;
    private final int port;
    private final Path clientCertPath;
    private final Path clientKeyPath;
    private final String clientKeyPassword;
    private final X509Certificate clientCert;
    private final PrivateKey clientKey;
    private final TransparencyClient transparencyClient;
    private final HttpAuthHeadersProvider httpAuthHeadersProvider;

    private ConnectOptions(Builder builder) {
        this.verificationPolicy = builder.verificationPolicy;
        this.port = builder.port;
        this.clientCertPath = builder.clientCertPath;
        this.clientKeyPath = builder.clientKeyPath;
        this.clientKeyPassword = builder.clientKeyPassword;
        this.clientCert = builder.clientCert;
        this.clientKey = builder.clientKey;
        this.transparencyClient = builder.transparencyClient;
        this.httpAuthHeadersProvider = builder.httpAuthHeadersProvider;
    }

    /**
     * Creates a new builder with default options.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns default connect options (PKI only, no additional verification).
     *
     * @return default options
     */
    public static ConnectOptions defaults() {
        return new Builder().build();
    }

    /**
     * Returns the verification policy.
     *
     * @return the verification policy, or PKI_ONLY if not set
     */
    public VerificationPolicy getVerificationPolicy() {
        return verificationPolicy != null ? verificationPolicy : VerificationPolicy.PKI_ONLY;
    }

    /**
     * Returns the port for TLSA lookup.
     *
     * @return the port (default: 443)
     */
    public int getPort() {
        return port;
    }

    /**
     * Returns the client certificate path.
     *
     * @return the certificate path, or null if not set
     */
    public Path getClientCertPath() {
        return clientCertPath;
    }

    /**
     * Returns the client key path.
     *
     * @return the key path, or null if not set
     */
    public Path getClientKeyPath() {
        return clientKeyPath;
    }

    /**
     * Returns the client key password.
     *
     * @return the password, or null if unencrypted
     */
    public String getClientKeyPassword() {
        return clientKeyPassword;
    }

    /**
     * Returns the client certificate.
     *
     * @return the certificate, or null if not set
     */
    public X509Certificate getClientCert() {
        return clientCert;
    }

    /**
     * Returns the client private key.
     *
     * @return the private key, or null if not set
     */
    public PrivateKey getClientKey() {
        return clientKey;
    }

    /**
     * Returns the custom transparency client, if configured.
     *
     * @return the transparency client, or null for default
     */
    public TransparencyClient getTransparencyClient() {
        return transparencyClient;
    }

    /**
     * Returns the authentication provider, if configured.
     *
     * <p>The auth provider adds custom headers (e.g., Authorization) to
     * each request made through the connection.</p>
     *
     * @return the auth provider, or null if not configured
     */
    public HttpAuthHeadersProvider getAuthProvider() {
        return httpAuthHeadersProvider;
    }

    /**
     * Checks if client certificate is configured.
     *
     * @return true if mTLS client cert is available
     */
    public boolean hasClientCertificate() {
        return (clientCertPath != null && clientKeyPath != null)
            || (clientCert != null && clientKey != null);
    }

    // ==================== Builder ====================

    /**
     * Builder for ConnectOptions.
     */
    public static final class Builder {
        private VerificationPolicy verificationPolicy;
        private int port = 443;
        private Path clientCertPath;
        private Path clientKeyPath;
        private String clientKeyPassword;
        private X509Certificate clientCert;
        private PrivateKey clientKey;
        private TransparencyClient transparencyClient;
        private HttpAuthHeadersProvider httpAuthHeadersProvider;

        private Builder() {
        }

        /**
         * Sets the verification policy.
         *
         * <p>Use this to configure which verification methods to use.</p>
         *
         * @param policy the verification policy
         * @return this builder
         * @see VerificationPolicy#BADGE_REQUIRED
         * @see VerificationPolicy#DANE_AND_BADGE
         * @see VerificationPolicy#custom()
         */
        public Builder verificationPolicy(VerificationPolicy policy) {
            this.verificationPolicy = Objects.requireNonNull(policy, "Verification policy cannot be null");
            return this;
        }

        /**
         * Sets the port for TLSA lookup.
         *
         * <p>Default is 443. Change this if the target server uses a non-standard
         * HTTPS port and has TLSA records published for that port.</p>
         *
         * @param port the port number
         * @return this builder
         */
        public Builder port(int port) {
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port must be between 1 and 65535");
            }
            this.port = port;
            return this;
        }

        /**
         * Sets the client certificate from PEM file paths.
         *
         * @param certPath path to the client certificate PEM file
         * @param keyPath path to the client private key PEM file
         * @return this builder
         */
        public Builder clientCertPath(Path certPath, Path keyPath) {
            this.clientCertPath = requireNonEmptyPath(certPath, "Certificate path");
            this.clientKeyPath = requireNonEmptyPath(keyPath, "Key path");
            return this;
        }

        /**
         * Sets the client certificate path (certificate file).
         *
         * @param certPath path to the client certificate PEM file
         * @return this builder
         */
        public Builder clientCertPath(Path certPath) {
            this.clientCertPath = requireNonEmptyPath(certPath, "Certificate path");
            return this;
        }

        /**
         * Sets the client key path.
         *
         * @param keyPath path to the client private key PEM file
         * @return this builder
         */
        public Builder clientKeyPath(Path keyPath) {
            this.clientKeyPath = requireNonEmptyPath(keyPath, "Key path");
            return this;
        }

        private static Path requireNonEmptyPath(Path path, String name) {
            if (path == null) {
                throw new IllegalArgumentException(name + " cannot be null");
            }
            if (path.toString().isEmpty()) {
                throw new IllegalArgumentException(name + " cannot be empty");
            }
            return path;
        }

        /**
         * Sets the password for the client private key.
         *
         * <p>Only needed if the private key is encrypted.</p>
         *
         * @param password the key password, or null if unencrypted
         * @return this builder
         */
        public Builder clientKeyPassword(String password) {
            this.clientKeyPassword = password;
            return this;
        }

        /**
         * Sets the client certificate and key directly.
         *
         * <p>Use this instead of file paths if you've already loaded the certificate.</p>
         *
         * @param cert the client certificate
         * @param key the client private key
         * @return this builder
         */
        public Builder clientCertificate(X509Certificate cert, PrivateKey key) {
            this.clientCert = Objects.requireNonNull(cert, "Certificate cannot be null");
            this.clientKey = Objects.requireNonNull(key, "Private key cannot be null");
            return this;
        }

        /**
         * Sets a custom transparency client.
         *
         * <p>If not set, a default client will be created when identity
         * verification is enabled.</p>
         *
         * @param client the transparency client
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient client) {
            this.transparencyClient = client;
            return this;
        }

        /**
         * Sets the authentication provider.
         *
         * <p>The auth provider adds custom headers (e.g., Authorization) to
         * each request. Use the factory methods on {@link HttpAuthHeadersProvider} for
         * common authentication schemes:</p>
         *
         * <pre>{@code
         * // Bearer token
         * .authProvider(AuthProvider.bearer("eyJhbGciOiJSUzI1NiIs..."))
         *
         * // API key (sso-key format)
         * .authProvider(AuthProvider.apiKey("my-key", "my-secret"))
         *
         * // Custom header
         * .authProvider(AuthProvider.header("X-Custom-Auth", "value"))
         * }</pre>
         *
         * @param provider the auth provider
         * @return this builder
         */
        public Builder authProvider(HttpAuthHeadersProvider provider) {
            this.httpAuthHeadersProvider = provider;
            return this;
        }

        /**
         * Builds the ConnectOptions.
         *
         * @return the configured options
         */
        public ConnectOptions build() {
            // Validate client cert configuration
            if ((clientCertPath == null) != (clientKeyPath == null)) {
                throw new IllegalStateException(
                    "Both clientCertPath and clientKeyPath must be set together");
            }
            if ((clientCert == null) != (clientKey == null)) {
                throw new IllegalStateException(
                    "Both clientCert and clientKey must be set together");
            }

            return new ConnectOptions(this);
        }
    }

    @Override
    public String toString() {
        return "ConnectOptions{" +
            "verificationPolicy=" + getVerificationPolicy() +
            ", port=" + port +
            ", hasClientCert=" + hasClientCertificate() +
            ", hasAuthProvider=" + (httpAuthHeadersProvider != null) +
            '}';
    }
}