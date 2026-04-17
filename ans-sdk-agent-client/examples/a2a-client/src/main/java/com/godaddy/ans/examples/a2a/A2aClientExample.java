package com.godaddy.ans.examples.a2a;

import com.godaddy.ans.sdk.agent.AnsConnection;
import com.godaddy.ans.sdk.agent.AnsVerifiedClient;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.http.AnsVerifiedSslContextFactory;
import com.godaddy.ans.sdk.agent.http.CertificateCapturingTrustManager;
import com.godaddy.ans.sdk.agent.verification.BadgeVerifier;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DaneConfig;
import com.godaddy.ans.sdk.agent.verification.DaneVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.godaddy.ans.sdk.agent.verification.DnssecValidationMode;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.verification.BadgeVerificationService;

import io.a2a.A2A;
import io.a2a.client.Client;
import io.a2a.client.ClientEvent;
import io.a2a.client.MessageEvent;
import io.a2a.client.TaskEvent;
import io.a2a.client.http.A2ACardResolver;
import io.a2a.client.transport.jsonrpc.JSONRPCTransport;
import io.a2a.client.transport.jsonrpc.JSONRPCTransportConfig;
import io.a2a.spec.AgentCard;
import io.a2a.spec.Message;
import io.a2a.spec.Part;
import io.a2a.spec.TextPart;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * A2A Client Example - demonstrates ANS verification with the A2A SDK.
 *
 * <p>This example shows how to integrate ANS verification (DANE, Badge, SCITT)
 * with the official A2A (Agent-to-Agent) Java SDK.</p>
 *
 * <h2>Examples</h2>
 * <ul>
 *   <li><b>Example 1: Manual Verification</b> - Low-level DANE/Badge verification flow</li>
 *   <li><b>Example 2: SCITT with AnsVerifiedClient</b> - High-level SCITT verification</li>
 * </ul>
 *
 * <h2>Integration Pattern (Manual)</h2>
 * <ol>
 *   <li>Create {@link HttpClientA2AAdapter} with SSLContext from {@link AnsVerifiedSslContextFactory}</li>
 *   <li>Pre-verify (DANE lookup) before connection</li>
 *   <li>Fetch AgentCard - TLS handshake captures certificate</li>
 *   <li>Post-verify captured certificate against expectations</li>
 *   <li>Create A2A client and send messages</li>
 * </ol>
 *
 * <h2>Integration Pattern (SCITT with AnsVerifiedClient)</h2>
 * <ol>
 *   <li>Create {@link AnsVerifiedClient} with keystore and policy</li>
 *   <li>Call connect() - handles preflight and SCITT header exchange</li>
 *   <li>Use SSLContext and SCITT headers with A2A client</li>
 *   <li>Call verifyServer() after TLS handshake</li>
 * </ol>
 *
 * <h2>Prerequisites</h2>
 * <ol>
 *   <li>A running A2A server with HTTPS endpoint</li>
 *   <li>For DANE verification: TLSA DNS records configured</li>
 *   <li>For Badge verification: Agent registered in ANS transparency log</li>
 *   <li>For SCITT verification: Agent with receipt and status token</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 * # Run with default settings (DANE/Badge example)
 * ./gradlew :ans-sdk-agent-client:examples:a2a-client:run
 *
 * # Run with custom server URL
 * ./gradlew :ans-sdk-agent-client:examples:a2a-client:run --args="https://your-server:8443"
 *
 * # Run SCITT example with keystore
 * ./gradlew :ans-sdk-agent-client:examples:a2a-client:run \
 *   --args="https://your-server:8443 /path/to/client.p12 password agentId"
 * </pre>
 */
public class A2aClientExample {

    public static void main(String[] args) {
        // Parse command line arguments
        String serverUrl = args.length > 0 ? args[0] : "https://your-a2a-server.example.com:8443";

        System.out.println("===========================================");
        System.out.println("ANS SDK - A2A Client Example");
        System.out.println("===========================================");
        System.out.println("Target: " + serverUrl);
        System.out.println();

        try {
            // Example 1: Manual DANE/Badge verification
            a2aWithAnsVerification(serverUrl);

            // Example 2: SCITT verification (requires keystore arguments)
            if (args.length >= 4) {
                String keystorePath = args[1];
                String keystorePassword = args[2];
                String agentId = args[3];
                a2aWithScittVerification(serverUrl, keystorePath, keystorePassword, agentId);
            } else {
                System.out.println("\n===========================================");
                System.out.println("SCITT Example (Skipped)");
                System.out.println("===========================================");
                System.out.println("To run SCITT example, provide:");
                System.out.println("  --args=\"<serverUrl> <keystorePath> <keystorePassword> <agentId>\"");
            }

            System.out.println("\n===========================================");
            System.out.println("Examples completed!");
            System.out.println("===========================================");
        } catch (Exception e) {
            System.err.println("Example failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Demonstrates A2A SDK integration with ANS verification.
     */
    private static void a2aWithAnsVerification(String serverUrl) throws Exception {
        URI serverUri = URI.create(serverUrl);
        String hostname = serverUri.getHost();
        int port = serverUri.getPort() == -1 ? 443 : serverUri.getPort();

        // ============================================================
        // STEP 1: Set up the ANS ConnectionVerifier
        // ============================================================
        System.out.println("Step 1: Setting up ANS ConnectionVerifier");
        System.out.println("-".repeat(40));

        ConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(new DaneVerifier(new DefaultDaneTlsaVerifier(
                    DaneConfig.builder().validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
                            .build())))
            .badgeVerifier(new BadgeVerifier(
                BadgeVerificationService.builder()
                    .transparencyClient(TransparencyClient.createOte())
                    .build()))
            .build();

        System.out.println("  Created verifier with DANE and Badge support");

        // ============================================================
        // STEP 2: Pre-verify (async - can be cached)
        // ============================================================
        System.out.println("\nStep 2: Pre-verification (DANE lookup)");
        System.out.println("-".repeat(40));

        CompletableFuture<PreVerificationResult> preResultFuture = verifier.preVerify(hostname, port);
        System.out.println("  Started async pre-verification for " + hostname + ":" + port);

        // ============================================================
        // STEP 3: Create SSLContext with certificate capture
        // ============================================================
        System.out.println("\nStep 3: Creating SSLContext with certificate capture");
        System.out.println("-".repeat(40));

        AnsVerifiedSslContextFactory.SslContextResult sslResult =
            AnsVerifiedSslContextFactory.createWithTrustManager(null, null);
        SSLContext sslContext = sslResult.sslContext();
        CertificateCapturingTrustManager trustManager = sslResult.trustManager();
        System.out.println("  Created SSLContext with CertificateCapturingTrustManager");

        // ============================================================
        // STEP 4: Create A2A HTTP client with custom SSLContext
        // ============================================================
        System.out.println("\nStep 4: Creating A2A HTTP client adapter");
        System.out.println("-".repeat(40));

        HttpClientA2AAdapter httpClient = new HttpClientA2AAdapter(sslContext);
        System.out.println("  Created HttpClientA2AAdapter with ANS-enabled SSLContext");

        // ============================================================
        // STEP 5: Get AgentCard (triggers TLS handshake)
        // ============================================================
        System.out.println("\nStep 5: Fetching AgentCard");
        System.out.println("-".repeat(40));

        A2ACardResolver cardResolver = new A2ACardResolver(httpClient, serverUrl, null);
        AgentCard agentCard = cardResolver.getAgentCard();

        System.out.println("  AgentCard fetched:");
        System.out.println("    Name: " + agentCard.name());
        System.out.println("    Description: " + agentCard.description());

        // ============================================================
        // STEP 6: Post-verify the captured certificate
        // ============================================================
        System.out.println("\nStep 6: Post-verification");
        System.out.println("-".repeat(40));

        PreVerificationResult preResult = preResultFuture.join();
        X509Certificate[] capturedCerts = trustManager.getInstanceCapturedCertificates(hostname);

        if (capturedCerts == null || capturedCerts.length == 0) {
            throw new SecurityException("No certificate captured for " + hostname);
        }

        X509Certificate serverCert = capturedCerts[0];
        System.out.println("  Captured certificate: " + serverCert.getSubjectX500Principal());

        List<VerificationResult> results = verifier.postVerify(hostname, serverCert, preResult);

        System.out.println("\n  ANS Verification Results:");
        for (VerificationResult result : results) {
            String status = result.isSuccess() ? "PASS" : "FAIL";
            System.out.println("    " + result.type() + ": " + status);
            if (!result.isSuccess() && result.reason() != null) {
                System.out.println("      Reason: " + result.reason());
            }
        }

        // Apply verification policy
        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_REQUIRED);
        System.out.println("\n  Combined result (DANE_REQUIRED policy): " +
            (combined.isSuccess() ? "PASS" : "FAIL - " + combined.reason()));

        if (!combined.isSuccess()) {
            throw new SecurityException("ANS verification failed: " + combined.reason());
        }

        // ============================================================
        // STEP 7: Create A2A client and send message
        // ============================================================
        System.out.println("\nStep 7: Sending A2A message");
        System.out.println("-".repeat(40));

        CompletableFuture<String> responseFuture = new CompletableFuture<>();

        BiConsumer<ClientEvent, AgentCard> eventHandler = getClientEventAgentCardBiConsumer(responseFuture);

        JSONRPCTransportConfig transportConfig = new JSONRPCTransportConfig(httpClient);

        Client client = Client.builder(agentCard)
            .withTransport(JSONRPCTransport.class, transportConfig)
            .addConsumer(eventHandler)
            .build();

        try {
            Message message = A2A.toUserMessage("Hello from ANS-verified A2A client!");
            System.out.println("  Sending message: \"Hello from ANS-verified A2A client!\"");

            client.sendMessage(message);

            String response = responseFuture.get(30, TimeUnit.SECONDS);
            System.out.println("  Response: " + response);
            System.out.println("\n  Successfully communicated with ANS-verified A2A server!");

        } finally {
            // Clean up
            trustManager.clearInstanceCapturedCertificates(hostname);
        }
    }

    /**
     * Demonstrates A2A SDK integration with SCITT verification using AnsVerifiedClient.
     *
     * <p>This is the recommended approach for SCITT-enabled A2A communication.
     * AnsVerifiedClient handles:</p>
     * <ul>
     *   <li>Preflight requests to exchange SCITT headers</li>
     *   <li>SSLContext creation with certificate capture</li>
     *   <li>SCITT artifact verification</li>
     * </ul>
     *
     * @param serverUrl the A2A server URL
     * @param keystorePath path to PKCS12 keystore for client mTLS
     * @param keystorePassword keystore password
     * @param agentId agent ID for SCITT header generation
     */
    private static void a2aWithScittVerification(String serverUrl, String keystorePath,
                                                  String keystorePassword, String agentId) throws Exception {
        System.out.println("\n===========================================");
        System.out.println("Example 2: A2A with SCITT Verification");
        System.out.println("===========================================");

        // ============================================================
        // STEP 1: Create AnsVerifiedClient with SCITT policy
        // ============================================================
        System.out.println("\nStep 1: Creating AnsVerifiedClient");
        System.out.println("-".repeat(40));

        try (AnsVerifiedClient ansClient = AnsVerifiedClient.builder()
                .agentId(agentId)
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.OTE_BASE_URL).build())
                .keyStorePath(keystorePath, keystorePassword)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .build()) {

            System.out.println("  Policy: " + ansClient.policy());
            // Fetch SCITT headers (blocking is fine during setup, not on I/O threads)
            var scittHeaders = ansClient.fetchScittHeadersAsync().join();
            if (!scittHeaders.isEmpty()) {
                System.out.println("  SCITT headers configured for outgoing requests");
            }

            // ============================================================
            // STEP 2: Connect (performs preflight for SCITT)
            // ============================================================
            System.out.println("\nStep 2: Connecting with SCITT preflight");
            System.out.println("-".repeat(40));

            try (AnsConnection connection = ansClient.connect(serverUrl)) {
                System.out.println("  Connected to: " + connection.hostname());
                System.out.println("  SCITT artifacts from server: " + connection.hasScittArtifacts());

                // ============================================================
                // STEP 3: Create A2A HTTP client with ANS SSLContext
                // ============================================================
                System.out.println("\nStep 3: Creating A2A client");
                System.out.println("-".repeat(40));

                HttpClientA2AAdapter httpClient = new HttpClientA2AAdapter(ansClient.sslContext());
                System.out.println("  Created HttpClientA2AAdapter with ANS SSLContext");

                // ============================================================
                // STEP 4: Fetch AgentCard (triggers TLS handshake)
                // ============================================================
                System.out.println("\nStep 4: Fetching AgentCard");
                System.out.println("-".repeat(40));

                A2ACardResolver cardResolver = new A2ACardResolver(httpClient, serverUrl, null);
                AgentCard agentCard = cardResolver.getAgentCard();

                System.out.println("  AgentCard fetched:");
                System.out.println("    Name: " + agentCard.name());
                System.out.println("    Description: " + agentCard.description());

                // ============================================================
                // STEP 5: Post-verify server certificate
                // ============================================================
                System.out.println("\nStep 5: Post-verification (SCITT + captured cert)");
                System.out.println("-".repeat(40));

                VerificationResult result = connection.verifyServer();

                System.out.println("  Verification: " + result.status() + " (" + result.type() + ")");
                System.out.println("  Reason: " + result.reason());

                if (!result.isSuccess()) {
                    throw new SecurityException("SCITT verification failed: " + result.reason());
                }

                // ============================================================
                // STEP 6: Create A2A client and send message
                // ============================================================
                System.out.println("\nStep 6: Sending A2A message");

                System.out.println("-".repeat(40));

                CompletableFuture<String> responseFuture = new CompletableFuture<>();

                BiConsumer<ClientEvent, AgentCard> eventHandler = getClientEventAgentCardBiConsumer(responseFuture);

                JSONRPCTransportConfig transportConfig = new JSONRPCTransportConfig(httpClient);

                Client client = Client.builder(agentCard)
                    .withTransport(JSONRPCTransport.class, transportConfig)
                    .addConsumer(eventHandler)
                    .build();

                Message message = A2A.toUserMessage("Hello from SCITT-verified A2A client!");
                System.out.println("  Sending message: \"Hello from SCITT-verified A2A client!\"");

                client.sendMessage(message);

                String response = responseFuture.get(30, TimeUnit.SECONDS);
                System.out.println("  Response: " + response);
                System.out.println("\n  Successfully communicated with SCITT-verified A2A server!");
                // AnsConnection.close() handles certificate cleanup via the provider
            }
        }
    }

    private static BiConsumer<ClientEvent, AgentCard> getClientEventAgentCardBiConsumer(
            CompletableFuture<String> responseFuture) {
        return (event, card) -> {
            System.out.println("  Received event: " + event.getClass().getSimpleName());
            if (event instanceof MessageEvent messageEvent) {
                Message msg = messageEvent.getMessage();
                for (Part<?> part : msg.parts()) {
                    if (part instanceof TextPart textPart) {
                        responseFuture.complete(textPart.text());
                    }
                }
            } else if (event instanceof TaskEvent taskEvent) {
                System.out.println("    Task status: " + taskEvent.getTask().status());
            }
        };
    }
}