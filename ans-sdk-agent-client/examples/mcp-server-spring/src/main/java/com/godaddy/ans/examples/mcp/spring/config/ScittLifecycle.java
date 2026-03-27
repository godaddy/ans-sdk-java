package com.godaddy.ans.examples.mcp.spring.config;

import com.godaddy.ans.sdk.transparency.scitt.ScittArtifactManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

/**
 * Manages the lifecycle of SCITT artifact background refresh.
 *
 * <p>Implements {@link SmartLifecycle} to ensure background refresh starts
 * after all beans are created and stops before they are destroyed.</p>
 */
@Component
public class ScittLifecycle implements SmartLifecycle {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScittLifecycle.class);

    private final McpServerProperties properties;
    private final ScittArtifactManager artifactManager;
    private volatile boolean running = false;

    public ScittLifecycle(McpServerProperties properties, ScittArtifactManager artifactManager) {
        this.properties = properties;
        this.artifactManager = artifactManager;
    }

    @Override
    public void start() {
        String agentId = properties.getAgentId();
        if (agentId != null && !agentId.isBlank()) {
            LOGGER.info("Starting SCITT artifact management for agent: {}", agentId);

            // Pre-fetch both artifacts to warm the cache before first request
            LOGGER.info("Pre-fetching SCITT artifacts for agent: {}", agentId);
            artifactManager.getReceipt(agentId)
                .thenAccept(receipt -> LOGGER.info("Receipt pre-fetched (tree size: {})",
                    receipt.inclusionProof().treeSize()))
                .exceptionally(e -> {
                    LOGGER.warn("Failed to pre-fetch receipt: {}", e.getMessage());
                    return null;
                });
            artifactManager.getStatusToken(agentId)
                .thenAccept(token -> LOGGER.info("Status token pre-fetched (expires: {})", token.expiresAt()))
                .exceptionally(e -> {
                    LOGGER.warn("Failed to pre-fetch status token: {}", e.getMessage());
                    return null;
                });

            // Start background refresh to keep status token fresh
            artifactManager.startBackgroundRefresh(agentId);
            running = true;
        } else {
            LOGGER.warn("No agent ID configured - SCITT artifact refresh not started");
        }
    }

    @Override
    public void stop() {
        if (running) {
            String agentId = properties.getAgentId();
            if (agentId != null && !agentId.isBlank()) {
                LOGGER.info("Stopping SCITT artifact background refresh for agent: {}", agentId);
                artifactManager.stopBackgroundRefresh(agentId);
            }
            running = false;
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        // Start late (after other beans), stop early (before other beans)
        return Integer.MAX_VALUE - 100;
    }
}
