package com.godaddy.ans.sdk.agent.exception;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Tests for ProtocolException.
 */
class ProtocolExceptionTest {

    @Test
    void constructorWithMessageOnly() {
        ProtocolException ex = new ProtocolException("Invalid response");

        assertEquals("Invalid response", ex.getMessage());
        assertNull(ex.getCause());
        assertNull(ex.getProtocol());
        assertEquals(0, ex.getStatusCode());
        assertNull(ex.getRequestId());
    }

    @Test
    void constructorWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("Parse error");
        ProtocolException ex = new ProtocolException("Invalid response", cause);

        assertEquals("Invalid response", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertNull(ex.getProtocol());
        assertEquals(0, ex.getStatusCode());
    }

    @Test
    void constructorWithMessageProtocolAndStatusCode() {
        ProtocolException ex = new ProtocolException("Server error", "A2A", 500);

        assertEquals("Server error", ex.getMessage());
        assertEquals("A2A", ex.getProtocol());
        assertEquals(500, ex.getStatusCode());
        assertNull(ex.getCause());
    }

    @Test
    void constructorWithAllParameters() {
        RuntimeException cause = new RuntimeException("JSON parse error");
        ProtocolException ex = new ProtocolException(
            "Invalid response", cause, "MCP", 400, "req-456");

        assertEquals("Invalid response", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals("MCP", ex.getProtocol());
        assertEquals(400, ex.getStatusCode());
        assertEquals("req-456", ex.getRequestId());
    }

    @Test
    void variousHttpStatusCodes() {
        ProtocolException notFound = new ProtocolException("Not found", "HTTP-API", 404);
        assertEquals(404, notFound.getStatusCode());

        ProtocolException unauthorized = new ProtocolException("Unauthorized", "A2A", 401);
        assertEquals(401, unauthorized.getStatusCode());

        ProtocolException serverError = new ProtocolException("Internal error", "MCP", 500);
        assertEquals(500, serverError.getStatusCode());
    }

    @Test
    void zeroStatusCodeIsValid() {
        ProtocolException ex = new ProtocolException("Non-HTTP error", "A2A", 0);

        assertEquals(0, ex.getStatusCode());
        assertEquals("A2A", ex.getProtocol());
    }
}
