package com.godaddy.ans.examples.mcp.spring;

import com.godaddy.ans.examples.mcp.spring.config.McpServerProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import java.security.Security;

/**
 * Spring Boot MCP Server with ANS verification.
 *
 * <p>This example demonstrates a production-ready MCP server that:</p>
 * <ul>
 *   <li>Automatically refreshes SCITT artifacts (receipts and status tokens)</li>
 *   <li>Adds SCITT headers to all outgoing responses</li>
 *   <li>Verifies incoming client requests against SCITT artifacts</li>
 *   <li>Exposes SCITT health status via Spring Actuator</li>
 * </ul>
 *
 * <h2>Quick Start</h2>
 * <pre>
 * # Set required environment variables
 * export ANS_AGENT_ID=your-agent-uuid
 * export SSL_KEYSTORE_PATH=/path/to/keystore.p12
 * export SSL_KEYSTORE_PASSWORD=changeit
 * export SSL_TRUSTSTORE_PATH=/path/to/truststore.p12
 * export SSL_TRUSTSTORE_PASSWORD=changeit
 *
 * # Run the server
 * ./gradlew :ans-sdk-agent-client:examples:mcp-server-spring:bootRun
 * </pre>
 *
 * <h2>Health Check</h2>
 * <pre>
 * curl -k https://localhost:8443/actuator/health
 * </pre>
 *
 * @see com.godaddy.ans.examples.mcp.spring.config.ScittConfig
 * @see com.godaddy.ans.examples.mcp.spring.filter.ClientVerificationFilter
 * @see com.godaddy.ans.examples.mcp.spring.filter.ScittHeaderResponseFilter
 */
@SpringBootApplication
@EnableConfigurationProperties(McpServerProperties.class)
public class McpServerSpringApplication {

    private static final Logger LOGGER = LoggerFactory.getLogger(McpServerSpringApplication.class);

    public static void main(String[] args) {
        // Register BouncyCastle provider for PEM certificate handling
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("Registered BouncyCastle security provider");

        SpringApplication.run(McpServerSpringApplication.class, args);
    }
}
