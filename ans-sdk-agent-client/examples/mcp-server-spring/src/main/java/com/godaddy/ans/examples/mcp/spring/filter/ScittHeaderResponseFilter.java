package com.godaddy.ans.examples.mcp.spring.filter;

import com.godaddy.ans.examples.mcp.spring.config.McpServerProperties;
import com.godaddy.ans.sdk.transparency.scitt.ScittArtifactManager;
import com.godaddy.ans.sdk.transparency.scitt.ScittHeaders;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Servlet filter that adds SCITT headers to all outgoing responses.
 *
 * <p>This filter retrieves the current SCITT artifacts (receipt and status token)
 * from the {@link ScittArtifactManager} cache and adds them as Base64-encoded headers
 * to every HTTP response.</p>
 *
 * <p>Headers added:</p>
 * <ul>
 *   <li>{@code X-SCITT-Receipt} - Cryptographic proof of Transparency Log inclusion</li>
 *   <li>{@code X-ANS-Status-Token} - Time-bounded assertion of agent status</li>
 * </ul>
 *
 * <p>The artifact manager caches artifacts and refreshes them in the background,
 * so this filter benefits from cached values without making HTTP calls on each request.</p>
 *
 * @see ScittHeaders
 * @see ScittArtifactManager
 */
@Component
public class ScittHeaderResponseFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScittHeaderResponseFilter.class);
    private static final long ARTIFACT_TIMEOUT_SECONDS = 5;

    private final ScittArtifactManager artifactManager;
    private final String agentId;

    public ScittHeaderResponseFilter(
            ScittArtifactManager artifactManager,
            McpServerProperties properties) {
        this.artifactManager = artifactManager;
        this.agentId = properties.getAgentId();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (agentId == null || agentId.isBlank()) {
            // No agent ID configured - skip SCITT headers
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            // Fetch pre-computed Base64 artifacts concurrently
            CompletableFuture<String> receiptFuture = artifactManager.getReceiptBase64(agentId);
            CompletableFuture<String> tokenFuture = artifactManager.getStatusTokenBase64(agentId);

            // Wait for both with timeout
            String receipt = receiptFuture.get(ARTIFACT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            String token = tokenFuture.get(ARTIFACT_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            // Add SCITT headers
            if (receipt != null && !receipt.isEmpty()) {
                httpResponse.addHeader(ScittHeaders.SCITT_RECEIPT_HEADER, receipt);
                LOGGER.debug("Added SCITT receipt header for agent: {}", agentId);
            }

            if (token != null && !token.isEmpty()) {
                httpResponse.addHeader(ScittHeaders.STATUS_TOKEN_HEADER, token);
                LOGGER.debug("Added status token header for agent: {}", agentId);
            }

        } catch (Exception e) {
            LOGGER.warn("Failed to fetch SCITT artifacts for agent {}: {}", agentId, e.getMessage());
            // Continue without SCITT headers - graceful degradation
        }

        chain.doFilter(request, response);
    }
}
