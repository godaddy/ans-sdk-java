package com.godaddy.ans.examples.mcp;

import static com.godaddy.ans.sdk.agent.VerificationPolicy.SCITT_REQUIRED;

import com.godaddy.ans.sdk.agent.AnsConnection;
import com.godaddy.ans.sdk.agent.AnsVerifiedClient;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import com.godaddy.ans.sdk.transparency.TransparencyClient;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.ClientCapabilities;

import java.time.Duration;

/**
 * MCP Client Example - demonstrates ANS verification with the MCP SDK.
 *
 * <p>This example shows how to integrate ANS verification with the official
 * MCP (Model Context Protocol) Java SDK using the high-level {@link AnsVerifiedClient}.</p>
 *
 * <p>The client:</p>
 * <ul>
 *   <li>Automatically configures verification based on the selected policy</li>
 *   <li>Handles SCITT header generation and verification (if enabled)</li>
 *   <li>Supports DANE/TLSA, Badge, and SCITT verification methods</li>
 *   <li>Uses mTLS with an identity certificate for mutual authentication</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>
 * ./gradlew :ans-sdk-agent-client:examples:mcp-client:run
 * ./gradlew :ans-sdk-agent-client:examples:mcp-client:run --args="https://your-server.com/mcp"
 * </pre>
 *
 * <h2>Environment Variables</h2>
 * <ul>
 *   <li>AGENT_ID - Agent ID for client's own SCITT artifacts</li>
 *   <li>KEYSTORE_PATH - Path to client PKCS12 keystore containing identity cert + key</li>
 *   <li>KEYSTORE_PASS - Keystore password (default: changeit)</li>
 * </ul>
 *
 * <h2>Creating a Client Keystore</h2>
 * <pre>
 * # From PEM files:
 * openssl pkcs12 -export -in cert.pem -inkey key.pem -out client.p12 -name client -password pass:changeit
 *
 * # Include CA chain if needed:
 * openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile ca.pem -out client.p12 -name client
 * </pre>
 */
public class McpClientExample {

    private static final String DEFAULT_SERVER_URL = "https://your-mcp-server.example.com/mcp";

    public static void main(String[] args) throws Exception {
        String serverUrl = args.length > 0 ? args[0] : DEFAULT_SERVER_URL;

        // Client's own agent ID for SCITT headers (server verifies these)
        String agentId = System.getenv("AGENT_ID");

        // Client keystore for mTLS
        String keystorePath = System.getenv("KEYSTORE_PATH");
        String keystorePassword = System.getenv("KEYSTORE_PASS");

        // Policy can be set via environment: SCITT_REQUIRED (default), SCITT_ENHANCED, BADGE_REQUIRED, etc.
        VerificationPolicy policy = SCITT_REQUIRED;

        System.out.println("ANS SDK - MCP Client Example");
        System.out.println("Target: " + serverUrl);
        System.out.println("Policy: " + policy);
        System.out.println();

        // Create ANS verified client - handles all verification setup based on policy
        try (AnsVerifiedClient ansClient = AnsVerifiedClient.builder()
                .agentId(agentId)
                .transparencyClient(TransparencyClient.builder().baseUrl(TransparencyClient.OTE_BASE_URL).build())
                .keyStorePath(keystorePath, keystorePassword)
                .policy(policy)
                .build()) {

            // Fetch SCITT headers early (blocking is fine during setup)
            var scittHeaders = ansClient.fetchScittHeadersAsync().join();

            // Connect and run all pre-verifications (DANE, Badge, SCITT based on policy)
            try (AnsConnection connection = ansClient.connect(serverUrl)) {
                System.out.println("Pre-verification complete:");
                System.out.println("  DANE records: " + (connection.hasDaneRecords() ? "found" : "none"));
                System.out.println("  Badge registration: " + (connection.hasBadgeRegistration() ? "found" : "none"));
                System.out.println("  SCITT artifacts: " + (connection.hasScittArtifacts() ? "found" : "none"));

                // Create MCP client with ANS SSLContext and SCITT headers
                HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder(serverUrl)
                    .customizeClient(b -> b.sslContext(ansClient.sslContext())
                        .connectTimeout(Duration.ofSeconds(30)))
                    .customizeRequest(b -> scittHeaders.forEach(b::header))
                    .build();

                McpSyncClient mcpClient = McpClient.sync(transport)
                    .requestTimeout(Duration.ofSeconds(30))
                    .capabilities(ClientCapabilities.builder().roots(true).build())
                    .build();

                try {
                    mcpClient.initialize();

                    // Post-verify server certificate (combines all results per policy)
                    VerificationResult result = connection.verifyServer();
                    System.out.println("\nServer verification: " + (result.isSuccess() ? "PASS" : "FAIL"));
                    System.out.println("  Type: " + result.type());
                    if (result.reason() != null) {
                        System.out.println("  Reason: " + result.reason());
                    }

                    if (!result.isSuccess()) {
                        throw new SecurityException("Server verification failed: " + result.reason());
                    }

                    // Use verified client
                    var tools = mcpClient.listTools();
                    System.out.println("\nAvailable tools: " + tools.tools().size());
                    tools.tools().forEach(t -> System.out.println("  - " + t.name() + ": " + t.description()));

                } finally {
                    mcpClient.closeGracefully();
                }
            }
        }
    }
}
