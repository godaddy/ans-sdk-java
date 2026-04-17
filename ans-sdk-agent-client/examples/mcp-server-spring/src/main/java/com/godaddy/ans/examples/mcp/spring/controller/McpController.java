package com.godaddy.ans.examples.mcp.spring.controller;

import com.godaddy.ans.examples.mcp.spring.config.McpServerProperties;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpStatelessSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStatelessServerTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.json.JsonMapper;

/**
 * REST controller that handles MCP protocol requests.
 *
 * <p>Integrates the MCP SDK's servlet transport with Spring MVC. The MCP server
 * is configured with demo tools (hello, echo) for testing.</p>
 *
 * <p>Example usage:</p>
 * <pre>
 * POST /mcp
 * Content-Type: application/json
 *
 * {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
 * </pre>
 */
@RestController
@RequestMapping("/mcp")
public class McpController {

    private static final Logger LOGGER = LoggerFactory.getLogger(McpController.class);

    private final McpServerProperties properties;
    private HttpServletStatelessServerTransport transport;
    private McpStatelessSyncServer server;

    public McpController(McpServerProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        LOGGER.info("Initializing MCP server: {} v{}",
                properties.getServerInfo().getName(),
                properties.getServerInfo().getVersion());

        // Create JSON mapper using Jackson 3.x
        McpJsonMapper jsonMapper = new JacksonMcpJsonMapper(JsonMapper.builder().build());

        // Create stateless servlet transport
        transport = HttpServletStatelessServerTransport.builder()
                .jsonMapper(jsonMapper)
                .build();

        // Build MCP server with demo tools
        server = McpServer.sync(transport)
                .serverInfo(properties.getServerInfo().getName(), properties.getServerInfo().getVersion())
                .capabilities(ServerCapabilities.builder().tools(true).build())
                .tools(createHelloToolSpec(jsonMapper), createEchoToolSpec(jsonMapper))
                .build();

        LOGGER.info("MCP server initialized with tools: hello, echo");
    }

    @PreDestroy
    public void destroy() {
        if (server != null) {
            LOGGER.info("Shutting down MCP server");
            server.close();
        }
        if (transport != null) {
            transport.close();
        }
    }

    /**
     * Handles HEAD requests for endpoint availability checks.
     */
    @RequestMapping(method = RequestMethod.HEAD)
    public void handleHead() {
        // Returns 200 OK - MCP SDK uses HEAD to check endpoint availability
    }

    /**
     * Handles GET requests for SSE streaming.
     *
     * <p>Stateless servers don't push notifications, so we return an empty SSE stream
     * that closes immediately. This satisfies the MCP protocol without errors.</p>
     */
    @RequestMapping(method = RequestMethod.GET)
    public void handleSse(HttpServletResponse response) throws IOException {
        response.setContentType("text/event-stream");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-cache");
        response.setHeader("Connection", "keep-alive");
        response.getWriter().flush();
        // Stream closes immediately - no notifications from stateless server
    }

    /**
     * Handles MCP JSON-RPC requests.
     *
     * <p>At this point, the client has already been verified by
     * {@link com.godaddy.ans.examples.mcp.spring.filter.ClientVerificationFilter}
     * and SCITT headers will be added by
     * {@link com.godaddy.ans.examples.mcp.spring.filter.ScittHeaderResponseFilter}.</p>
     */
    @RequestMapping(method = RequestMethod.POST)
    public void handleMcp(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        LOGGER.debug("Handling MCP POST request");
        transport.service(request, response);
    }

    /**
     * Creates the hello tool specification.
     */
    private SyncToolSpecification createHelloToolSpec(McpJsonMapper jsonMapper) {
        Tool tool = Tool.builder()
                .name("hello")
                .description("Greets the user by name. A simple demo tool for testing.")
                .inputSchema(jsonMapper, """
                    {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The name to greet"
                            }
                        },
                        "required": ["name"]
                    }
                    """)
                .build();

        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((context, request) -> {
                    String name = "World";
                    if (request.arguments() != null && request.arguments().containsKey("name")) {
                        name = request.arguments().get("name").toString();
                    }
                    return CallToolResult.builder()
                            .addTextContent("Hello, " + name + "! Welcome to the ANS-verified MCP server.")
                            .build();
                })
                .build();
    }

    /**
     * Creates the echo tool specification.
     */
    private SyncToolSpecification createEchoToolSpec(McpJsonMapper jsonMapper) {
        Tool tool = Tool.builder()
                .name("echo")
                .description("Echoes back the provided message. Useful for testing connectivity.")
                .inputSchema(jsonMapper, """
                    {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "The message to echo"
                            }
                        },
                        "required": ["message"]
                    }
                    """)
                .build();

        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((context, request) -> {
                    String message = "";
                    if (request.arguments() != null && request.arguments().containsKey("message")) {
                        message = request.arguments().get("message").toString();
                    }
                    return CallToolResult.builder()
                            .addTextContent("Echo: " + message)
                            .build();
                })
                .build();
    }
}
