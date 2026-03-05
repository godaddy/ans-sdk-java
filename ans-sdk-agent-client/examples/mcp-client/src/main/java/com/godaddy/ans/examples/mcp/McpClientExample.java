package com.godaddy.ans.examples.mcp;

import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.http.AnsVerifiedSslContextFactory;
import com.godaddy.ans.sdk.agent.http.CertificateCapturingTrustManager;
import com.godaddy.ans.sdk.agent.verification.BadgeVerifier;
import com.godaddy.ans.sdk.agent.verification.ConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DaneConfig;
import com.godaddy.ans.sdk.agent.verification.DaneVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultConnectionVerifier;
import com.godaddy.ans.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.godaddy.ans.sdk.agent.verification.PreVerificationResult;
import com.godaddy.ans.sdk.agent.verification.VerificationResult;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.verification.BadgeVerificationService;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.ClientCapabilities;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * MCP Client Example - demonstrates ANS verification with the MCP SDK.
 *
 * <p>This example shows how to integrate ANS verification (DANE, Badge)
 * with the official MCP (Model Context Protocol) Java SDK.</p>
 *
 * <h2>Integration Pattern</h2>
 * <ol>
 *   <li>Create SSLContext with certificate capture using {@link AnsVerifiedSslContextFactory}</li>
 *   <li>Configure MCP transport with custom SSLContext</li>
 *   <li>Pre-verify (DANE lookup) before connection</li>
 *   <li>Connect - TLS handshake captures certificate</li>
 *   <li>Post-verify captured certificate against expectations</li>
 * </ol>
 *
 * <h2>Prerequisites</h2>
 * <ol>
 *   <li>A running MCP server with HTTPS endpoint</li>
 *   <li>For DANE verification: TLSA DNS records configured</li>
 *   <li>For Badge verification: Agent registered in ANS transparency log</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 * # Run with default settings
 * ./gradlew :ans-sdk-agent-client:examples:mcp-client:run
 *
 * # Run with custom server URL
 * ./gradlew :ans-sdk-agent-client:examples:mcp-client:run --args="https://your-mcp-server.example.com"
 * </pre>
 */
public class McpClientExample {

    public static void main(String[] args) {
        // Parse command line arguments
        String serverUrl = args.length > 0 ? args[0] : "https://your-mcp-server.example.com/mcp";

        System.out.println("===========================================");
        System.out.println("ANS SDK - MCP Client Example");
        System.out.println("===========================================");
        System.out.println("Target: " + serverUrl);
        System.out.println();

        try {
            mcpWithAnsVerification(serverUrl);
            System.out.println("\n===========================================");
            System.out.println("Example completed successfully!");
            System.out.println("===========================================");
        } catch (Exception e) {
            System.err.println("Example failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Demonstrates MCP SDK integration with ANS verification.
     */
    private static void mcpWithAnsVerification(String serverUrl) throws Exception {
        URI serverUri = URI.create(serverUrl);
        String hostname = serverUri.getHost();
        int port = serverUri.getPort() == -1 ? 443 : serverUri.getPort();

        // ============================================================
        // STEP 1: Set up the ANS ConnectionVerifier
        // ============================================================
        System.out.println("Step 1: Setting up ANS ConnectionVerifier");
        System.out.println("-".repeat(40));

        ConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(new DaneVerifier(new DefaultDaneTlsaVerifier(DaneConfig.defaults())))
            .badgeVerifier(new BadgeVerifier(
                BadgeVerificationService.builder()
                    .transparencyClient(TransparencyClient.builder().build())
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

        SSLContext sslContext = AnsVerifiedSslContextFactory.create();
        System.out.println("  Created SSLContext with CertificateCapturingTrustManager");

        // ============================================================
        // STEP 4: Create MCP transport with custom SSLContext
        // ============================================================
        System.out.println("\nStep 4: Creating MCP transport");
        System.out.println("-".repeat(40));

        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport
            .builder(serverUrl)
            .customizeClient(builder -> builder
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(30)))
            .build();

        System.out.println("  Created HttpClientStreamableHttpTransport with custom SSLContext");

        // ============================================================
        // STEP 5: Create MCP Client
        // ============================================================
        System.out.println("\nStep 5: Creating MCP client");
        System.out.println("-".repeat(40));

        McpSyncClient mcpClient = McpClient.sync(transport)
            .requestTimeout(Duration.ofSeconds(30))
            .capabilities(ClientCapabilities.builder()
                .roots(true)
                .build())
            .build();

        System.out.println("  Created McpSyncClient");

        try {
            // ============================================================
            // STEP 6: Initialize connection (triggers TLS handshake)
            // ============================================================
            System.out.println("\nStep 6: Initializing MCP connection");
            System.out.println("-".repeat(40));

            mcpClient.initialize();
            System.out.println("  MCP connection initialized");

            // ============================================================
            // STEP 7: Post-verify the captured certificate
            // ============================================================
            System.out.println("\nStep 7: Post-verification");
            System.out.println("-".repeat(40));

            PreVerificationResult preResult = preResultFuture.join();
            X509Certificate[] capturedCerts = CertificateCapturingTrustManager.getCapturedCertificates(hostname);

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
            VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);
            System.out.println("\n  Combined result (BADGE_REQUIRED policy): " +
                (combined.isSuccess() ? "PASS" : "FAIL - " + combined.reason()));

            if (!combined.isSuccess()) {
                throw new SecurityException("ANS verification failed: " + combined.reason());
            }

            // ============================================================
            // STEP 8: Use the verified MCP client
            // ============================================================
            System.out.println("\nStep 8: Using verified MCP client");
            System.out.println("-".repeat(40));

            var tools = mcpClient.listTools();
            System.out.println("  Available tools: " + tools.tools().size());

            for (var tool : tools.tools()) {
                System.out.println("    - " + tool.name() + ": " + tool.description());
            }

            System.out.println("\n  Successfully communicated with ANS-verified MCP server!");

        } finally {
            // Clean up
            CertificateCapturingTrustManager.clearCapturedCertificates(hostname);
            mcpClient.closeGracefully();
        }
    }
}
