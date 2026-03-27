package com.godaddy.ans.examples.mcp.spring.config;

import com.godaddy.ans.sdk.agent.verification.DefaultClientRequestVerifier;
import com.godaddy.ans.sdk.transparency.TransparencyClient;
import com.godaddy.ans.sdk.transparency.scitt.ScittArtifactManager;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for SCITT artifact management and client verification.
 *
 * <p>This configuration creates and manages the lifecycle of:</p>
 * <ul>
 *   <li>{@link TransparencyClient} - for fetching SCITT artifacts from the Transparency Log</li>
 *   <li>{@link ScittArtifactManager} - for caching and background refresh of artifacts</li>
 *   <li>{@link DefaultClientRequestVerifier} - for verifying incoming client requests</li>
 * </ul>
 *
 * <p>Background refresh is automatically started on application startup and stopped on shutdown.</p>
 */
@Configuration
public class ScittConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScittConfig.class);

    private final McpServerProperties properties;
    private ScittArtifactManager artifactManager;

    public ScittConfig(McpServerProperties properties) {
        this.properties = properties;
    }

    /**
     * Creates the Transparency Client for fetching SCITT artifacts.
     *
     * <p>Uses the configured SCITT domain from properties, defaulting to
     * the TransparencyClient's default (OTE) if not specified.</p>
     */
    @Bean
    public TransparencyClient transparencyClient() {
        String domain = properties.getScitt().getDomain();
        String baseUrl = "https://" + domain;
        LOGGER.info("Configuring TransparencyClient with baseUrl: {}", baseUrl);
        return TransparencyClient.builder()
                .baseUrl(baseUrl)
                .build();
    }

    /**
     * Creates the SCITT Artifact Manager for caching and background refresh.
     *
     * <p>The manager caches receipts indefinitely (they are immutable Merkle proofs)
     * and automatically refreshes status tokens before they expire.</p>
     */
    @Bean
    public ScittArtifactManager scittArtifactManager(TransparencyClient transparencyClient) {
        artifactManager = ScittArtifactManager.builder()
                .transparencyClient(transparencyClient)
                .build();
        return artifactManager;
    }

    /**
     * Creates the Client Request Verifier for validating incoming requests.
     *
     * <p>The verifier extracts SCITT artifacts from request headers, validates
     * cryptographic signatures, and matches client certificate fingerprints
     * against the status token's identity certificates.</p>
     *
     * <p>Features:</p>
     * <ul>
     *   <li>64KB header size limit (DoS protection)</li>
     *   <li>Constant-time fingerprint comparison (timing attack protection)</li>
     *   <li>Result caching based on (receipt hash, token hash, cert fingerprint)</li>
     * </ul>
     */
    @Bean
    public DefaultClientRequestVerifier clientRequestVerifier(TransparencyClient transparencyClient) {
        return DefaultClientRequestVerifier.builder()
                .transparencyClient(transparencyClient)
                .build();
    }

    /**
     * Stops background refresh and releases resources on shutdown.
     */
    @PreDestroy
    public void stopBackgroundRefresh() {
        if (artifactManager != null) {
            String agentId = properties.getAgentId();
            if (agentId != null && !agentId.isBlank()) {
                LOGGER.info("Stopping SCITT artifact background refresh for agent: {}", agentId);
                artifactManager.stopBackgroundRefresh(agentId);
            }
            artifactManager.close();
        }
    }
}
