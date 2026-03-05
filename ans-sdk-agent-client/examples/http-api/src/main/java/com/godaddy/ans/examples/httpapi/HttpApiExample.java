package com.godaddy.ans.examples.httpapi;

import com.godaddy.ans.sdk.agent.AnsClient;
import com.godaddy.ans.sdk.agent.ConnectOptions;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.connection.AgentConnection;
import com.godaddy.ans.sdk.agent.protocol.HttpApiClient;

import java.time.Duration;

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
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 * # Run with default settings
 * ./gradlew :ans-sdk-agent-client:examples:http-api:run
 *
 * # Run with custom server URL
 * ./gradlew :ans-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
 * </pre>
 *
 * <h2>Verification Policies</h2>
 * <ul>
 *   <li><b>PKI_ONLY</b> - Standard HTTPS with system trust store</li>
 *   <li><b>DANE_REQUIRED</b> - Requires DANE/TLSA verification</li>
 *   <li><b>BADGE_REQUIRED</b> - Requires transparency log verification</li>
 *   <li><b>DANE_AND_BADGE</b> - Requires both DANE and Badge</li>
 *   <li><b>FULL</b> - DANE + Badge (maximum security)</li>
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
                .verificationPolicy(VerificationPolicy.FULL)
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

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "null";
        }
        s = s.replace("\n", " ").trim();
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
