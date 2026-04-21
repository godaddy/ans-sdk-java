package com.godaddy.ans.examples.httpapi;

import com.godaddy.ans.sdk.agent.AnsClient;
import com.godaddy.ans.sdk.agent.AnsConnection;
import com.godaddy.ans.sdk.agent.AnsVerifiedClient;
import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.connection.AgentConnection;
import com.godaddy.ans.sdk.agent.protocol.HttpApiClient;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import com.godaddy.ans.sdk.transparency.TransparencyClient;

import java.time.Duration;
import java.util.Map;

/**
 * HTTP API Example - demonstrates ANS verification with AnsClient.
 *
 * <p>This example shows how to use the ANS SDK to make verified HTTP
 * connections to ANS-registered agents using different verification policies.</p>
 *
 * <h2>Prerequisites</h2>
 * <ol>
 *   <li>A running ANS-registered agent with HTTPS endpoint</li>
 *   <li>For DANE verification: TLSA DNS records configured</li>
 *   <li>For Badge verification: Agent registered in ANS transparency log</li>
 *   <li>For SCITT verification: Agent has SCITT receipt and status token</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 * # Run with default settings
 * ./gradlew :ans-sdk-agent-client:examples:http-api:run
 *
 * # Run with custom server URL
 * ./gradlew :ans-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
 *
 * # Run SCITT example with keystore and agent ID
 * ./gradlew :ans-sdk-agent-client:examples:http-api:run \
 *   --args="https://your-agent.example.com:8443 /path/to/keystore.p12 keystorePassword myAgentId"
 * </pre>
 *
 * <h2>Verification Policies</h2>
 * <ul>
 *   <li><b>PKI_ONLY</b> - Standard HTTPS with system trust store</li>
 *   <li><b>DANE_REQUIRED</b> - Requires DANE/TLSA verification</li>
 *   <li><b>BADGE_REQUIRED</b> - Requires transparency log verification</li>
 *   <li><b>DANE_AND_BADGE</b> - Requires both DANE and Badge</li>
 *   <li><b>SCITT_REQUIRED</b> - Requires SCITT receipt and status token verification (recommended)</li>
 * </ul>
 */
public class HttpApiExample {

    public static void main(String[] args) {
        // Parse command line arguments
        String serverUrl = args.length > 0 ? args[0] : "https://your-agent.example.com:8443";

        System.out.println("===========================================");
        System.out.println("ANS SDK - HTTP API Example");
        System.out.println("===========================================");
        System.out.println("Target: " + serverUrl);
        System.out.println();

        // Run examples with different verification policies
        examplePkiOnly(serverUrl);
        exampleBadgeRequired(serverUrl);
        exampleDaneAndBadge(serverUrl);

        // SCITT example requires keystore - check if arguments provided
        if (args.length >= 4) {
            String keystorePath = args[1];
            String keystorePassword = args[2];
            String agentId = args[3];
            exampleScittVerification(serverUrl, keystorePath, keystorePassword, agentId);
        } else {
            System.out.println("\nExample 4: SCITT Verification (Skipped)");
            System.out.println("-".repeat(40));
            System.out.println("  To run SCITT example, provide:");
            System.out.println("  ./gradlew :ans-sdk-agent-client:examples:http-api:run \\");
            System.out.println("    --args=\"<serverUrl> <keystorePath> <keystorePassword> <agentId>\"");
            System.out.println();
        }

        System.out.println("\n===========================================");
        System.out.println("Examples completed!");
        System.out.println("===========================================");
    }

    /**
     * Example 1: PKI_ONLY - Standard HTTPS.
     *
     * <p>Uses the system trust store for certificate validation.
     * This is the simplest approach but provides no ANS-specific verification.</p>
     */
    private static void examplePkiOnly(String serverUrl) {
        System.out.println("Example 1: PKI_ONLY - Standard HTTPS");
        System.out.println("-".repeat(40));

        try {
            // Create AnsClient with custom timeouts
            AnsClient client = AnsClient.builder()
                .connectTimeout(Duration.ofSeconds(10))
                .readTimeout(Duration.ofSeconds(30))
                .build();

            System.out.println("  Created AnsClient");

            // Connect with default PKI_ONLY policy
            AgentConnection conn = client.connect(serverUrl);
            System.out.println("  Connected with PKI_ONLY (default)");

            // Use the connection to make HTTP requests
            HttpApiClient api = conn.httpApiAt(serverUrl);

            String response = api.get("/health");
            System.out.println("  GET /health: " + truncate(response, 100));

            System.out.println("  [SUCCESS] PKI_ONLY example completed\n");

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage() + "\n");
        }
    }

    /**
     * Example 2: BADGE_REQUIRED - Transparency log verification.
     *
     * <p>Verifies the agent's certificate against the ANS transparency log.
     * This is the recommended approach for most use cases.</p>
     */
    private static void exampleBadgeRequired(String serverUrl) {
        System.out.println("Example 2: BADGE_REQUIRED - Transparency Log Verification");
        System.out.println("-".repeat(40));

        try {
            AnsClient client = AnsClient.create();
            System.out.println("  Created AnsClient");

            // Connect with BADGE_REQUIRED policy
            ConnectOptions options = ConnectOptions.builder()
                .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.OTE_BASE_URL).build())
                .build();

            System.out.println("  Connecting with: " + options.getVerificationPolicy());
            System.out.println("  Will verify certificate against ANS transparency log");

            AgentConnection conn = client.connect(serverUrl, options);
            System.out.println("  Connected with BADGE_REQUIRED");

            // Use the connection
            HttpApiClient api = conn.httpApiAt(serverUrl);
            String response = api.get("/health");
            System.out.println("  GET /health: " + truncate(response, 100));

            System.out.println("  [SUCCESS] BADGE_REQUIRED example completed\n");

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("transparency")) {
                System.out.println("  (Agent may not be registered in the transparency log)");
            }
            System.out.println();
        }
    }

    /**
     * Example 3: DANE + Badge verification (maximum security).
     *
     * <p>Demonstrates full verification with both DANE and Badge required.</p>
     */
    private static void exampleDaneAndBadge(String serverUrl) {
        System.out.println("Example 3: DANE + Badge (Full Verification)");
        System.out.println("-".repeat(40));

        try {
            AnsClient client = AnsClient.create();

            // Full policy: DANE + Badge
            ConnectOptions options = ConnectOptions.builder()
                .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.OTE_BASE_URL).build())
                .build();

            System.out.println("  Connecting with full verification policy:");
            System.out.println("    DANE: Required (verify TLSA DNS record)");
            System.out.println("    Badge: Required (verify transparency log)");

            AgentConnection conn = client.connect(serverUrl, options);
            HttpApiClient api = conn.httpApiAt(serverUrl);
            String response = api.get("/health");
            System.out.println("  GET /health: " + truncate(response, 100));

            System.out.println("  [SUCCESS] DANE + Badge example completed\n");

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("DANE")) {
                System.out.println("  (Agent may not have TLSA DNS records configured)");
            }
            System.out.println();
        }
    }

    /**
     * Example 4: SCITT Verification - Cryptographic proof via HTTP headers.
     *
     * <p>Uses AnsVerifiedClient for mTLS and SCITT verification.
     * Demonstrates the full verification flow including preflight requests
     * to exchange SCITT artifacts (receipts and status tokens).</p>
     *
     * @param serverUrl the server URL to connect to
     * @param keystorePath path to PKCS12 keystore for client authentication
     * @param keystorePassword keystore password
     * @param agentId the agent ID for SCITT header generation
     */
    private static void exampleScittVerification(String serverUrl, String keystorePath,
                                                  String keystorePassword, String agentId) {
        System.out.println("\nExample 4: SCITT Verification (Cryptographic Proof)");
        System.out.println("-".repeat(40));

        // Use try-with-resources to ensure proper cleanup on all paths
        try (AnsVerifiedClient client = AnsVerifiedClient.builder()
                .agentId(agentId)
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.OTE_BASE_URL).build())
                .keyStorePath(keystorePath, keystorePassword)
                .policy(VerificationPolicy.SCITT_REQUIRED)
                .connectTimeout(Duration.ofSeconds(30))
                .build()) {

            System.out.println("  Created AnsVerifiedClient with policy: " + client.policy());

            // Display SCITT headers that will be sent with requests
            // (blocking is fine during setup, not on I/O threads)
            Map<String, String> scittHeaders = client.fetchScittHeadersAsync().join();
            if (!scittHeaders.isEmpty()) {
                System.out.println("  SCITT headers configured:");
                scittHeaders.forEach((k, v) ->
                    System.out.println("    " + k + ": " + truncate(v, 50) + "..."));
            }

            // Connect and perform pre-verification
            // This sends a preflight HEAD request to exchange SCITT headers
            System.out.println("\n  Connecting to " + serverUrl);
            System.out.println("  (Preflight request will exchange SCITT artifacts)");

            try (AnsConnection connection = client.connect(serverUrl)) {
                System.out.println("  Connected to: " + connection.hostname());

                // Check if server provided SCITT artifacts
                if (connection.hasScittArtifacts()) {
                    System.out.println("  Server provided SCITT artifacts");
                } else {
                    System.out.println("  Server did not provide SCITT artifacts");
                }

                // Perform full verification
                VerificationResult result = connection.verifyServer();

                System.out.println("\n  Verification Results:");
                System.out.println("    Overall: " + result.status() + " (" + result.type() + ")");
                System.out.println("    Reason: " + result.reason());

                if (result.isSuccess()) {
                    System.out.println("\n  [SUCCESS] SCITT verification completed");
                } else {
                    System.out.println("\n  [WARNING] Verification status: " + result.status());
                }
            }
            System.out.println();

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
            if (e.getCause() != null) {
                System.out.println("  Cause: " + e.getCause().getMessage());
            }
            System.out.println();
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "null";
        }
        s = s.replace("\n", " ").trim();
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
