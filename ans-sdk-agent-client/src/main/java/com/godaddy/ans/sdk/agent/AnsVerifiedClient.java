package com.godaddy.ans.sdk.agent;

import com.godaddy.ans.sdk.agent.http.AnsVerifiedSslContextFactory;
import com.godaddy.ans.sdk.agent.verification.BadgeVerifier;
import com.godaddy.ans.sdk.agent.verification.DaneConfig;
import com.godaddy.ans.sdk.agent.verification.DaneVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.exception.ClientConfigurationException;
import com.godaddy.ans.sdk.agent.exception.ScittVerificationException;
import com.godaddy.ans.sdk.agent.verification.ScittVerifierAdapter;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.DefaultScittHeaderProvider;
import com.godaddy.ans.sdk.transparency.scitt.ScittPreVerifyResult;
import com.godaddy.ans.sdk.transparency.verification.CachingBadgeVerificationService;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * High-level client for ANS-verified connections.
 *
 * <p>Supports all verification policies:</p>
 * <ul>
 *   <li><b>DANE</b>: DNS-based Authentication of Named Entities (TLSA records)</li>
 *   <li><b>Badge</b>: ANS transparency log verification (proof of registration)</li>
 *   <li><b>SCITT</b>: Cryptographic proof via HTTP headers (receipts + status tokens)</li>
 * </ul>
 *
 * <h2>Usage with MCP SDK</h2>
 * <pre>{@code
 * AnsVerifiedClient ansClient = AnsVerifiedClient.builder()
 *     .agentId("my-agent-id")
 *     .keyStorePath("/path/to/client.p12", "password")
 *     .policy(VerificationPolicy.SCITT_REQUIRED)  // or SCITT_ENHANCED, etc.
 *     .build();
 *
 * AnsConnection connection = ansClient.connect(serverUrl);
 *
 * // Fetch SCITT headers (blocking in example code is fine during setup)
 * Map<String, String> scittHeaders = ansClient.scittHeadersAsync().join();
 *
 * HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder(serverUrl)
 *     .customizeClient(b -> b.sslContext(ansClient.sslContext()))
 *     .customizeRequest(b -> scittHeaders.forEach(b::header))
 *     .build();
 *
 * McpSyncClient mcpClient = McpClient.sync(transport).build();
 * mcpClient.initialize();
 *
 * VerificationResult result = connection.verifyServer();
 * }</pre>
 */
public class AnsVerifiedClient implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnsVerifiedClient.class);

    private final TransparencyClient transparencyClient;
    private final DefaultConnectionVerifier connectionVerifier;
    private final VerificationPolicy policy;
    private final SSLContext sslContext;
    private final HttpClient httpClient;
    private final String agentId;

    // Lazy-loaded SCITT headers with thread-safe initialization
    private volatile Map<String, String> scittHeaders;
    private final Object scittHeadersLock = new Object();

    private AnsVerifiedClient(Builder builder) {
        this.transparencyClient = builder.transparencyClient;
        this.connectionVerifier = builder.connectionVerifier;
        this.policy = builder.policy;
        this.sslContext = builder.sslContext;
        this.agentId = builder.agentId;

        // If SCITT is disabled or no agentId, headers are empty (no lazy fetch needed)
        if (!policy.hasScittVerification() || agentId == null || agentId.isBlank()) {
            this.scittHeaders = Map.of();
        }

        // Create shared HttpClient once at construction time
        // HttpClient is designed to be long-lived and maintains its own connection pool
        this.httpClient = HttpClient.newBuilder()
            .sslContext(sslContext)
            .connectTimeout(builder.connectTimeout)
            .build();
    }

    /**
     * Returns the SSLContext configured for mTLS and certificate capture.
     *
     * @return the configured SSLContext
     */
    public SSLContext sslContext() {
        return sslContext;
    }

    /**
     * Returns SCITT headers asynchronously.
     *
     * <p>If headers haven't been fetched yet and SCITT is enabled with an agent ID,
     * this method initiates an async fetch of the receipt and status token from the
     * transparency log. The returned future completes when headers are available.</p>
     *
     * <p>The future completes with an empty map if:</p>
     * <ul>
     *   <li>SCITT verification is disabled in the policy</li>
     *   <li>No agent ID was configured</li>
     *   <li>Fetching artifacts failed (logged as warning)</li>
     * </ul>
     *
     * @return a CompletableFuture with the unmodifiable map of SCITT headers
     */
    public CompletableFuture<Map<String, String>> scittHeadersAsync() {
        // Fast path: already initialized
        if (scittHeaders != null) {
            return CompletableFuture.completedFuture(scittHeaders);
        }

        // Lazy fetch with double-checked locking
        return fetchScittHeadersAsync();
    }

    /**
     * Fetches SCITT headers lazily with thread-safe initialization.
     */
    private CompletableFuture<Map<String, String>> fetchScittHeadersAsync() {
        // Double-check after acquiring would-be lock position in async chain
        if (scittHeaders != null) {
            return CompletableFuture.completedFuture(scittHeaders);
        }

        LOGGER.debug("Fetching SCITT artifacts for agent {} (lazy)", agentId);

        // Fetch receipt and token in parallel
        CompletableFuture<byte[]> receiptFuture = transparencyClient.getReceiptAsync(agentId);
        CompletableFuture<byte[]> tokenFuture = transparencyClient.getStatusTokenAsync(agentId);

        return receiptFuture.thenCombine(tokenFuture, (receipt, token) -> {
            synchronized (scittHeadersLock) {
                // Double-check inside synchronized block
                if (scittHeaders != null) {
                    return scittHeaders;
                }

                Map<String, String> headers = Map.copyOf(DefaultScittHeaderProvider.builder()
                    .receipt(receipt)
                    .statusToken(token)
                    .build()
                    .getOutgoingHeaders());

                LOGGER.debug("Fetched SCITT artifacts: receipt={} bytes, token={} bytes",
                    receipt.length, token.length);

                scittHeaders = headers;
                return headers;
            }
        }).exceptionally(e -> {
            synchronized (scittHeadersLock) {
                if (scittHeaders != null) {
                    return scittHeaders;
                }
                LOGGER.warn("Could not fetch SCITT artifacts for agent {}: {}", agentId, e.getMessage());
                scittHeaders = Map.of();
                return scittHeaders;
            }
        });
    }

    /**
     * Returns the verification policy in use.
     *
     * @return the verification policy
     */
    public VerificationPolicy policy() {
        return policy;
    }

    /**
     * Returns the TransparencyClient for advanced use cases.
     *
     * @return the transparency client
     */
    public TransparencyClient transparencyClient() {
        return transparencyClient;
    }

    /**
     * Connects to a server and performs all enabled pre-verifications.
     *
     * <p><b>Blocking:</b> This method blocks the calling thread until all pre-verifications
     * complete. For non-blocking behavior in reactive contexts or virtual threads, use
     * {@link #connectAsync(String)} instead.</p>
     *
     * <p>Based on the policy, this may:</p>
     * <ul>
     *   <li>Send preflight HEAD request to capture SCITT headers (if SCITT enabled)</li>
     *   <li>Lookup DANE/TLSA DNS records (if DANE enabled)</li>
     *   <li>Query transparency log for badge (if Badge enabled)</li>
     * </ul>
     *
     * @param serverUrl the server URL to connect to
     * @return an AnsConnection for post-verification
     * @throws java.util.concurrent.CompletionException if a critical error occurs during connection
     * @see #connectAsync(String) for the non-blocking equivalent
     */
    public AnsConnection connect(String serverUrl) {
        return connectAsync(serverUrl).join();
    }

    /**
     * Connects to a server asynchronously and performs all enabled pre-verifications.
     *
     * <p>This method is non-blocking and returns immediately with a {@link CompletableFuture}
     * that completes when all pre-verifications are finished. Use this method in reactive
     * contexts, virtual threads, or when composing with other async operations.</p>
     *
     * <p>Based on the policy, this may:</p>
     * <ul>
     *   <li>Send preflight HEAD request to capture SCITT headers (if SCITT enabled)</li>
     *   <li>Lookup DANE/TLSA DNS records (if DANE enabled)</li>
     *   <li>Query transparency log for badge (if Badge enabled)</li>
     * </ul>
     *
     * <p>The returned future completes exceptionally if a critical error occurs during
     * pre-verification setup (e.g., malformed URL). Network errors from individual
     * verifications are captured in the {@link PreVerificationResult} rather than
     * failing the future.</p>
     *
     * @param serverUrl the server URL to connect to
     * @return a CompletableFuture that completes with an AnsConnection for post-verification
     * @see #connect(String) for the blocking equivalent
     */
    public CompletableFuture<AnsConnection> connectAsync(String serverUrl) {
        URI uri;
        try {
            uri = URI.create(serverUrl);
        } catch (IllegalArgumentException e) {
            return CompletableFuture.failedFuture(e);
        }

        String hostname = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : 443;

        LOGGER.debug("Connecting async to {}:{} with policy {}", hostname, port, policy);

        // Start DANE/Badge pre-verification asynchronously
        CompletableFuture<PreVerificationResult> daneAndBadgeFuture =
            connectionVerifier.preVerify(hostname, port);

        // Start SCITT preflight asynchronously (if enabled) so it runs in parallel with DANE/Badge
        CompletableFuture<ScittPreVerifyResult> scittFuture;
        if (policy.hasScittVerification()) {
            scittFuture = sendPreflightAsync(uri)
                .thenCompose(connectionVerifier::scittPreVerify)
                .exceptionally(e -> {
                    Throwable cause = e instanceof CompletionException && e.getCause() != null
                        ? e.getCause() : e;
                    LOGGER.warn("SCITT preflight failed: {}", cause.getMessage());
                    return ScittPreVerifyResult.parseError("Preflight failed: " + cause.getMessage());
                });
        } else {
            scittFuture = CompletableFuture.completedFuture(ScittPreVerifyResult.notPresent());
        }

        // Non-blocking: combine both futures using thenCombine
        return daneAndBadgeFuture.thenCombine(scittFuture, (preResult, scittPreResult) -> {
            // Fail-fast based on policy and SCITT result
            // This prevents accidental unverified connections
            boolean scittVerified = scittPreResult.expectation().isVerified();
            boolean scittPresent = scittPreResult.isPresent();

            if (policy.scittMode() == VerificationMode.REQUIRED && !scittVerified) {
                // REQUIRED: must have valid SCITT - reject if missing OR if verification failed
                String reason = scittPreResult.expectation().failureReason();
                ScittVerificationException.FailureType failureType = mapToFailureType(
                    scittPreResult.expectation().status());
                throw new ScittVerificationException(
                    "SCITT verification required but failed: " + reason, failureType);
            }

            if (policy.scittMode() == VerificationMode.ADVISORY && scittPresent && !scittVerified) {
                // ADVISORY: if headers ARE present but failed, reject (don't allow garbage headers)
                // If headers are NOT present, allow fallback to badge
                String reason = scittPreResult.expectation().failureReason();
                ScittVerificationException.FailureType failureType = mapToFailureType(
                    scittPreResult.expectation().status());
                throw new ScittVerificationException(
                    "SCITT headers present but verification failed: " + reason, failureType);
            }

            PreVerificationResult combinedResult = preResult.withScittResult(scittPreResult);
            LOGGER.debug("Pre-verification complete: {}", combinedResult);
            return new AnsConnection(hostname, combinedResult, connectionVerifier, policy);
        });
    }

    /**
     * Sends a preflight HEAD request asynchronously to capture server's SCITT headers.
     * Uses HttpClient.sendAsync for non-blocking I/O, enabling parallelism with DANE/Badge.
     * First fetches our SCITT headers (if not already cached) to include in the request.
     */
    private CompletableFuture<Map<String, String>> sendPreflightAsync(URI uri) {
        LOGGER.debug("Sending async preflight request to {}", uri);

        // First get our SCITT headers (lazy fetch if needed), then send the request
        return scittHeadersAsync().thenCompose(outgoingHeaders -> {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .method("HEAD", HttpRequest.BodyPublishers.noBody());
            outgoingHeaders.forEach(requestBuilder::header);

            return httpClient.sendAsync(requestBuilder.build(), HttpResponse.BodyHandlers.discarding())
                .thenApply(response -> {
                    Map<String, String> headers = new HashMap<>();
                    response.headers().map().forEach((k, v) -> {
                        if (!v.isEmpty()) {
                            headers.put(k.toLowerCase(), v.get(0));
                        }
                    });
                    LOGGER.debug("Preflight response: {} with {} headers",
                        response.statusCode(), headers.size());
                    return headers;
                });
        });
    }

    /**
     * Maps ScittExpectation.Status to ScittVerificationException.FailureType.
     */
    private static ScittVerificationException.FailureType mapToFailureType(
            com.godaddy.ans.sdk.transparency.scitt.ScittExpectation.Status status) {
        return switch (status) {
            case NOT_PRESENT -> ScittVerificationException.FailureType.HEADERS_NOT_PRESENT;
            case PARSE_ERROR -> ScittVerificationException.FailureType.PARSE_ERROR;
            case INVALID_RECEIPT, INVALID_TOKEN -> ScittVerificationException.FailureType.INVALID_SIGNATURE;
            case TOKEN_EXPIRED -> ScittVerificationException.FailureType.TOKEN_EXPIRED;
            case KEY_NOT_FOUND -> ScittVerificationException.FailureType.KEY_NOT_FOUND;
            case AGENT_REVOKED -> ScittVerificationException.FailureType.AGENT_REVOKED;
            case AGENT_INACTIVE -> ScittVerificationException.FailureType.AGENT_INACTIVE;
            case VERIFIED -> ScittVerificationException.FailureType.VERIFICATION_ERROR; // Should not happen
        };
    }

    @Override
    public void close() {
        // TransparencyClient doesn't require explicit close
        LOGGER.debug("AnsVerifiedClient closed");
    }

    /**
     * Creates a new builder for AnsVerifiedClient.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for AnsVerifiedClient.
     */
    public static class Builder {
        private String agentId;
        private KeyStore keyStore;
        private char[] keyPassword;
        private String keyStorePath;
        private TransparencyClient transparencyClient;
        private VerificationPolicy policy = VerificationPolicy.SCITT_REQUIRED;
        private Duration connectTimeout = Duration.ofSeconds(30);
        private SSLContext sslContext;
        private DefaultConnectionVerifier connectionVerifier;

        /**
         * Sets the agent ID for SCITT header generation.
         *
         * @param agentId the agent's unique identifier
         * @return this builder
         */
        public Builder agentId(String agentId) {
            this.agentId = agentId;
            return this;
        }

        /**
         * Sets the keystore for mTLS client authentication.
         *
         * @param keyStore the PKCS12 keystore containing client certificate
         * @param password the keystore password
         * @return this builder
         */
        public Builder keyStore(KeyStore keyStore, char[] password) {
            this.keyStore = keyStore;
            this.keyPassword = password;
            return this;
        }

        /**
         * Sets the keystore path for mTLS client authentication.
         *
         * @param path the path to the PKCS12 keystore
         * @param password the keystore password
         * @return this builder
         */
        public Builder keyStorePath(String path, String password) {
            this.keyStorePath = path;
            this.keyPassword = password.toCharArray();
            return this;
        }

        /**
         * Sets a custom TransparencyClient.
         *
         * @param client the transparency client
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient client) {
            this.transparencyClient = client;
            return this;
        }

        /**
         * Sets the verification policy.
         *
         * @param policy the verification policy (default: SCITT_REQUIRED)
         * @return this builder
         */
        public Builder policy(VerificationPolicy policy) {
            this.policy = Objects.requireNonNull(policy);
            return this;
        }

        /**
         * Sets the connection timeout for preflight requests.
         *
         * @param timeout the timeout (default: 30 seconds)
         * @return this builder
         */
        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = timeout;
            return this;
        }

        /**
         * Builds the AnsVerifiedClient.
         *
         * @return the configured client
         * @throws ClientConfigurationException if keystore loading or SSLContext creation fails
         */
        public AnsVerifiedClient build() {
            // Create TransparencyClient if not provided
            if (transparencyClient == null) {
                transparencyClient = TransparencyClient.builder().build();
            }

            // Load keystore if path provided
            if (keyStore == null && keyStorePath != null) {
                try {
                    keyStore = KeyStore.getInstance("PKCS12");
                    try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                        keyStore.load(fis, keyPassword);
                    }
                    LOGGER.debug("Loaded keystore from {}", keyStorePath);
                } catch (Exception e) {
                    throw new ClientConfigurationException("Failed to load keystore: " + e.getMessage(), e);
                }
            }

            // Create SSLContext
            try {
                sslContext = AnsVerifiedSslContextFactory.create(keyStore, keyPassword);
            } catch (GeneralSecurityException e) {
                throw new ClientConfigurationException("Failed to create SSLContext: " + e.getMessage(), e);
            } finally {
                if (keyPassword != null) {
                    Arrays.fill(keyPassword, '\0');
                    keyPassword = null;
                }
            }

            // Build ConnectionVerifier based on policy
            DefaultConnectionVerifier.Builder verifierBuilder = DefaultConnectionVerifier.builder();

            // DANE verifier (if enabled)
            if (policy.daneMode() != VerificationMode.DISABLED) {
                DefaultDaneTlsaVerifier tlsaVerifier = new DefaultDaneTlsaVerifier(DaneConfig.defaults());
                verifierBuilder.daneVerifier(new DaneVerifier(tlsaVerifier));
                LOGGER.debug("DANE verification enabled with mode {}", policy.daneMode());
            }

            // Badge verifier (if enabled)
            if (policy.badgeMode() != VerificationMode.DISABLED) {
                CachingBadgeVerificationService badgeService = CachingBadgeVerificationService.create();
                verifierBuilder.badgeVerifier(new BadgeVerifier(badgeService));
                LOGGER.debug("Badge verification enabled with mode {}", policy.badgeMode());
            }

            // SCITT verifier (if enabled)
            if (policy.scittMode() != VerificationMode.DISABLED) {
                ScittVerifierAdapter scittVerifier = ScittVerifierAdapter.builder()
                    .transparencyClient(transparencyClient)
                    .build();
                verifierBuilder.scittVerifier(scittVerifier);
                LOGGER.debug("SCITT verification enabled with mode {}", policy.scittMode());
                // Note: SCITT headers are fetched lazily on first call to scittHeaders()
            }

            connectionVerifier = verifierBuilder.build();
            return new AnsVerifiedClient(this);
        }
    }
}
