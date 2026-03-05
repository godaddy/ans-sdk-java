package com.godaddy.ans.sdk.agent.exception;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Tests for AgentConnectionException.
 */
class AgentConnectionExceptionTest {

    @Test
    void constructorWithMessageOnly() {
        AgentConnectionException ex = new AgentConnectionException("Connection failed");

        assertEquals("Connection failed", ex.getMessage());
        assertNull(ex.getCause());
        assertNull(ex.getTargetAgentHost());
        assertNull(ex.getRequestId());
    }

    @Test
    void constructorWithMessageAndTargetHost() {
        AgentConnectionException ex = new AgentConnectionException("Connection failed", "agent.example.com");

        assertEquals("Connection failed", ex.getMessage());
        assertEquals("agent.example.com", ex.getTargetAgentHost());
        assertNull(ex.getCause());
        assertNull(ex.getRequestId());
    }

    @Test
    void constructorWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("Network error");
        AgentConnectionException ex = new AgentConnectionException("Connection failed", cause);

        assertEquals("Connection failed", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertNull(ex.getTargetAgentHost());
        assertNull(ex.getRequestId());
    }

    @Test
    void constructorWithMessageCauseAndTargetHost() {
        RuntimeException cause = new RuntimeException("Timeout");
        AgentConnectionException ex = new AgentConnectionException("Connection failed", cause, "agent.example.com");

        assertEquals("Connection failed", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals("agent.example.com", ex.getTargetAgentHost());
        assertNull(ex.getRequestId());
    }

    @Test
    void constructorWithAllParameters() {
        RuntimeException cause = new RuntimeException("TLS handshake failed");
        AgentConnectionException ex = new AgentConnectionException(
            "Connection failed", cause, "agent.example.com", "req-123");

        assertEquals("Connection failed", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals("agent.example.com", ex.getTargetAgentHost());
        assertEquals("req-123", ex.getRequestId());
    }

    @Test
    void constructorWithNullValues() {
        AgentConnectionException ex = new AgentConnectionException(null, null, null, null);

        assertNull(ex.getMessage());
        assertNull(ex.getCause());
        assertNull(ex.getTargetAgentHost());
        assertNull(ex.getRequestId());
    }
}
