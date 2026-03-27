package com.godaddy.ans.examples.mcp.spring.filter;

import com.godaddy.ans.examples.mcp.spring.config.McpServerProperties;
import com.godaddy.ans.sdk.agent.VerificationMode;
import com.godaddy.ans.sdk.agent.VerificationPolicy;
import com.godaddy.ans.sdk.agent.verification.ClientRequestVerificationResult;
import com.godaddy.ans.sdk.agent.verification.DefaultClientRequestVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Servlet filter that verifies incoming client requests against SCITT artifacts.
 *
 * <p>This filter extracts the client certificate from mTLS and SCITT headers from
 * the request, then uses {@link DefaultClientRequestVerifier} to validate:</p>
 * <ul>
 *   <li>SCITT receipt signature (proof of Transparency Log inclusion)</li>
 *   <li>Status token signature and validity period</li>
 *   <li>Client certificate fingerprint against identity certs in token</li>
 * </ul>
 *
 * <p>Security features provided by the SDK verifier:</p>
 * <ul>
 *   <li>64KB header size limit (DoS protection)</li>
 *   <li>Constant-time fingerprint comparison (timing attack protection)</li>
 *   <li>Result caching based on (receipt hash, token hash, cert fingerprint)</li>
 * </ul>
 *
 * <p>On successful verification, the verified agent ID is stored as a request
 * attribute for downstream use.</p>
 *
 * @see DefaultClientRequestVerifier
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE) // Run first
public class ClientVerificationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientVerificationFilter.class);
    private static final long VERIFICATION_TIMEOUT_SECONDS = 5;

    /**
     * Request attribute key for the verified agent ID.
     */
    public static final String VERIFIED_AGENT_ID_ATTR = "ans.verified.agentId";

    /**
     * Request attribute key for the full verification result.
     */
    public static final String VERIFICATION_RESULT_ATTR = "ans.verification.result";

    private final DefaultClientRequestVerifier verifier;
    private final boolean verificationEnabled;
    private final VerificationPolicy policy;

    public ClientVerificationFilter(
            DefaultClientRequestVerifier verifier,
            McpServerProperties properties) {
        this.verifier = verifier;
        this.verificationEnabled = properties.getVerification().isEnabled();
        this.policy = properties.getVerification().getVerificationPolicy();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!verificationEnabled) {
            LOGGER.debug("Client verification disabled - skipping");
            filterChain.doFilter(request, response);
            return;
        }

        // Extract client certificate from mTLS
        X509Certificate[] certs = (X509Certificate[])
                request.getAttribute("jakarta.servlet.request.X509Certificate");

        if (certs == null || certs.length == 0) {
            // No client certificate - check if verification is required
            if (policy.scittMode() == VerificationMode.REQUIRED) {
                LOGGER.warn("Client certificate required but not provided");
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "Client certificate required for SCITT verification");
                return;
            }
            LOGGER.debug("No client certificate - proceeding without verification");
            filterChain.doFilter(request, response);
            return;
        }

        X509Certificate clientCert = certs[0];
        LOGGER.debug("Verifying client certificate: {}", clientCert.getSubjectX500Principal());

        // Extract all headers for verification
        Map<String, String> headers = extractHeaders(request);

        try {
            // Verify using SDK (handles caching, fingerprint matching internally)
            ClientRequestVerificationResult result = verifier
                    .verify(clientCert, headers, policy)
                    .get(VERIFICATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            // Store result for downstream use
            request.setAttribute(VERIFICATION_RESULT_ATTR, result);

            if (!result.verified()) {
                LOGGER.warn("Client verification failed: {}", result.errors());

                if (policy.scittMode() == VerificationMode.REQUIRED) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN,
                            "Client verification failed: " + String.join(", ", result.errors()));
                    return;
                }
                // Advisory mode - log warning but continue
                LOGGER.info("Proceeding despite verification failure (advisory mode)");
            } else {
                // Verification successful
                String agentId = result.agentId();
                request.setAttribute(VERIFIED_AGENT_ID_ATTR, agentId);
                LOGGER.info("Verified agent: {} (verification took {}ms)",
                        agentId, result.verificationDuration().toMillis());
            }

        } catch (Exception e) {
            LOGGER.error("Verification error: {}", e.getMessage(), e);

            if (policy.scittMode() == VerificationMode.REQUIRED) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "Verification error: " + e.getMessage());
                return;
            }
            // Advisory mode - continue despite error
            LOGGER.warn("Proceeding despite verification error (advisory mode)");
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts all HTTP headers from the request.
     *
     * <p>For headers with multiple values, only the first value is used.</p>
     */
    private Map<String, String> extractHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();

        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            String value = request.getHeader(name);
            headers.put(name, value);
        }

        return headers;
    }
}
