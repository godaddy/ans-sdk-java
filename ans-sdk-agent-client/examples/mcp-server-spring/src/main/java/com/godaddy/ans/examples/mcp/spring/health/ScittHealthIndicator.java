package com.godaddy.ans.examples.mcp.spring.health;

import com.godaddy.ans.examples.mcp.spring.config.McpServerProperties;
import com.godaddy.ans.sdk.transparency.scitt.ScittArtifactManager;
import com.godaddy.ans.sdk.transparency.scitt.StatusToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Health indicator that exposes SCITT artifact status to /actuator/health.
 *
 * <p>Provides visibility into:</p>
 * <ul>
 *   <li>Agent ID being served</li>
 *   <li>Status token expiration and time remaining</li>
 *   <li>Whether artifacts are stale (refresh failed)</li>
 *   <li>Token status (ACTIVE, WARNING, EXPIRED)</li>
 * </ul>
 *
 * <p>Example output:</p>
 * <pre>
 * {
 *   "status": "UP",
 *   "details": {
 *     "agentId": "abc-123",
 *     "tokenStatus": "ACTIVE",
 *     "tokenExpiration": "2024-01-15T10:30:00Z",
 *     "timeRemaining": "PT2H30M",
 *     "stale": false
 *   }
 * }
 * </pre>
 */
@Component
public class ScittHealthIndicator implements HealthIndicator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScittHealthIndicator.class);

    /**
     * Warn if token expires within this duration.
     */
    private static final Duration WARNING_THRESHOLD = Duration.ofMinutes(30);

    private final ScittArtifactManager artifactManager;
    private final String agentId;

    public ScittHealthIndicator(
            ScittArtifactManager artifactManager,
            McpServerProperties properties) {
        this.artifactManager = artifactManager;
        this.agentId = properties.getAgentId();
    }

    @Override
    public Health health() {
        if (agentId == null || agentId.isBlank()) {
            return Health.unknown()
                    .withDetail("reason", "No agent ID configured")
                    .build();
        }

        try {
            // Try to get current status token (cached, non-blocking if available)
            StatusToken token = artifactManager.getStatusToken(agentId)
                    .get(2, TimeUnit.SECONDS);

            if (token == null) {
                return Health.down()
                        .withDetail("agentId", agentId)
                        .withDetail("reason", "No status token available")
                        .withDetail("stale", true)
                        .build();
            }

            Instant now = Instant.now();
            Instant expiration = token.expiresAt();

            // Handle case where expiration is not set
            if (expiration == null) {
                return Health.up()
                        .withDetail("agentId", agentId)
                        .withDetail("tokenStatus", TokenStatus.ACTIVE.name())
                        .withDetail("tokenExpiration", "none")
                        .withDetail("stale", false)
                        .build();
            }

            Duration timeRemaining = Duration.between(now, expiration);

            // Determine token status
            TokenStatus status;
            Health.Builder healthBuilder;

            if (timeRemaining.isNegative()) {
                status = TokenStatus.EXPIRED;
                healthBuilder = Health.down();
            } else if (timeRemaining.compareTo(WARNING_THRESHOLD) < 0) {
                status = TokenStatus.WARNING;
                healthBuilder = Health.status("WARNING");
            } else {
                status = TokenStatus.ACTIVE;
                healthBuilder = Health.up();
            }

            return healthBuilder
                    .withDetail("agentId", agentId)
                    .withDetail("tokenStatus", status.name())
                    .withDetail("tokenExpiration", expiration.toString())
                    .withDetail("timeRemaining", formatDuration(timeRemaining))
                    .withDetail("tokenIssuedAt", token.issuedAt() != null ? token.issuedAt().toString() : "unknown")
                    .withDetail("stale", false)
                    .build();

        } catch (Exception e) {
            LOGGER.warn("Failed to check SCITT health for agent {}: {}", agentId, e.getMessage());

            return Health.down()
                    .withDetail("agentId", agentId)
                    .withDetail("reason", "Failed to fetch status token: " + e.getMessage())
                    .withDetail("stale", true)
                    .build();
        }
    }

    /**
     * Formats a duration in a human-readable format.
     */
    private String formatDuration(Duration duration) {
        if (duration.isNegative()) {
            return "EXPIRED";
        }

        long hours = duration.toHours();
        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();

        if (hours > 0) {
            return String.format("%dh %dm %ds", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%dm %ds", minutes, seconds);
        } else {
            return String.format("%ds", seconds);
        }
    }

    /**
     * Token status levels.
     */
    private enum TokenStatus {
        /**
         * Token is valid and has sufficient time remaining.
         */
        ACTIVE,

        /**
         * Token is valid but expiring soon.
         */
        WARNING,

        /**
         * Token has expired.
         */
        EXPIRED
    }
}
