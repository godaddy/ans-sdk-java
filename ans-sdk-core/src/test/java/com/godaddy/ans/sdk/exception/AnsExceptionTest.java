package com.godaddy.ans.sdk.exception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for ANS exception hierarchy.
 */
class AnsExceptionTest {

    @Test
    @DisplayName("AnsException should store message and request ID")
    void ansExceptionShouldStoreMessageAndRequestId() {
        AnsException exception = new AnsException("Test error", "req-123");

        assertThat(exception.getMessage()).isEqualTo("Test error");
        assertThat(exception.getRequestId()).isEqualTo("req-123");
    }

    @Test
    @DisplayName("AnsException should store cause")
    void ansExceptionShouldStoreCause() {
        RuntimeException cause = new RuntimeException("Original error");
        AnsException exception = new AnsException("Test error", cause, "req-123");

        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("AnsAuthenticationException should store message and request ID")
    void authExceptionShouldStoreMessageAndRequestId() {
        AnsAuthenticationException exception = new AnsAuthenticationException(
            "Auth failed", null, "req-456");

        assertThat(exception.getMessage()).isEqualTo("Auth failed");
        assertThat(exception.getRequestId()).isEqualTo("req-456");
    }

    @Test
    @DisplayName("AnsAuthenticationException should work with simple constructor")
    void authExceptionShouldWorkWithSimpleConstructor() {
        AnsAuthenticationException exception = new AnsAuthenticationException("Auth failed");

        assertThat(exception.getMessage()).isEqualTo("Auth failed");
    }

    @Test
    @DisplayName("AnsNotFoundException should store resource information")
    void notFoundExceptionShouldStoreResourceInfo() {
        AnsNotFoundException exception = new AnsNotFoundException(
            "Agent not found", "agent", "agent-123", "req-789");

        assertThat(exception.getMessage()).isEqualTo("Agent not found");
        assertThat(exception.getResourceType()).isEqualTo("agent");
        assertThat(exception.getResourceId()).isEqualTo("agent-123");
        assertThat(exception.getRequestId()).isEqualTo("req-789");
    }

    @Test
    @DisplayName("AnsValidationException should store field errors")
    void validationExceptionShouldStoreErrors() {
        Map<String, String> errors = Map.of(
            "agentHost", "must not be blank",
            "version", "invalid semver"
        );

        AnsValidationException exception = new AnsValidationException(
            "Validation failed", errors, "req-101");

        assertThat(exception.getMessage()).isEqualTo("Validation failed");
        assertThat(exception.getFieldErrors()).containsKey("agentHost");
        assertThat(exception.getFieldErrors().get("agentHost")).isEqualTo("must not be blank");
        assertThat(exception.getFieldErrors().get("version")).isEqualTo("invalid semver");
    }

    @Test
    @DisplayName("AnsValidationException should handle null errors")
    void validationExceptionShouldHandleNullErrors() {
        AnsValidationException exception = new AnsValidationException(
            "Validation failed", null, "req-102");

        assertThat(exception.getFieldErrors()).isEmpty();
    }

    @Test
    @DisplayName("AnsValidationException should work with simple constructor")
    void validationExceptionShouldWorkWithSimpleConstructor() {
        AnsValidationException exception = new AnsValidationException("Validation failed");

        assertThat(exception.getMessage()).isEqualTo("Validation failed");
        assertThat(exception.getFieldErrors()).isEmpty();
    }

    @Test
    @DisplayName("AnsServerException should store status code")
    void serverExceptionShouldStoreStatusCode() {
        AnsServerException exception = new AnsServerException(
            "Internal server error", 500, "req-500");

        assertThat(exception.getMessage()).isEqualTo("Internal server error");
        assertThat(exception.getStatusCode()).isEqualTo(500);
        assertThat(exception.getRequestId()).isEqualTo("req-500");
    }

    @Test
    @DisplayName("AnsServerException should store cause")
    void serverExceptionShouldStoreCause() {
        RuntimeException cause = new RuntimeException("Network error");
        AnsServerException exception = new AnsServerException(
            "Server error", 502, cause, "req-502");

        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getStatusCode()).isEqualTo(502);
    }

    @Test
    @DisplayName("All exceptions should extend AnsException")
    void allExceptionsShouldExtendAnsException() {
        assertThat(new AnsAuthenticationException("msg"))
            .isInstanceOf(AnsException.class);
        assertThat(new AnsNotFoundException("msg", null, null, null))
            .isInstanceOf(AnsException.class);
        assertThat(new AnsValidationException("msg"))
            .isInstanceOf(AnsException.class);
        assertThat(new AnsServerException("msg", 500, null))
            .isInstanceOf(AnsException.class);
    }

    @Test
    @DisplayName("All exceptions should extend RuntimeException")
    void allExceptionsShouldExtendRuntimeException() {
        assertThat(new AnsException("msg", "req"))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("AnsConflictException should store message")
    void conflictExceptionShouldStoreMessage() {
        AnsConflictException exception = new AnsConflictException("Resource already exists");

        assertThat(exception.getMessage()).isEqualTo("Resource already exists");
    }

    @Test
    @DisplayName("AnsConflictException should store message and request ID")
    void conflictExceptionShouldStoreMessageAndRequestId() {
        AnsConflictException exception = new AnsConflictException(
            "Agent already registered", "req-409");

        assertThat(exception.getMessage()).isEqualTo("Agent already registered");
        assertThat(exception.getRequestId()).isEqualTo("req-409");
    }

    @Test
    @DisplayName("AnsConflictException should extend AnsException")
    void conflictExceptionShouldExtendAnsException() {
        assertThat(new AnsConflictException("msg"))
            .isInstanceOf(AnsException.class);
    }

    @Test
    @DisplayName("AnsValidationException with field errors via two-arg constructor")
    void validationExceptionTwoArgConstructorWithFieldErrors() {
        Map<String, String> errors = Map.of("field1", "error1");
        AnsValidationException exception = new AnsValidationException("Validation failed", errors);

        assertThat(exception.getMessage()).isEqualTo("Validation failed");
        assertThat(exception.getFieldErrors()).containsEntry("field1", "error1");
    }

    @Test
    @DisplayName("AnsNotFoundException simple constructor")
    void notFoundExceptionSimpleConstructor() {
        AnsNotFoundException exception = new AnsNotFoundException(
            "Not found", "type", "id", null);

        assertThat(exception.getMessage()).isEqualTo("Not found");
        assertThat(exception.getResourceType()).isEqualTo("type");
        assertThat(exception.getResourceId()).isEqualTo("id");
        assertThat(exception.getRequestId()).isNull();
    }

    // Additional tests for full coverage

    @Test
    @DisplayName("AnsException message-only constructor")
    void ansExceptionMessageOnlyConstructor() {
        AnsException exception = new AnsException("Simple error");

        assertThat(exception.getMessage()).isEqualTo("Simple error");
        assertThat(exception.getRequestId()).isNull();
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("AnsException message and cause constructor")
    void ansExceptionMessageAndCauseConstructor() {
        RuntimeException cause = new RuntimeException("Root cause");
        AnsException exception = new AnsException("Error with cause", cause);

        assertThat(exception.getMessage()).isEqualTo("Error with cause");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getRequestId()).isNull();
    }

    @Test
    @DisplayName("AnsNotFoundException single-arg constructor")
    void notFoundExceptionSingleArgConstructor() {
        AnsNotFoundException exception = new AnsNotFoundException("Resource not found");

        assertThat(exception.getMessage()).isEqualTo("Resource not found");
        assertThat(exception.getResourceType()).isNull();
        assertThat(exception.getResourceId()).isNull();
    }

    @Test
    @DisplayName("AnsNotFoundException two-arg constructor creates message from resource")
    void notFoundExceptionTwoArgConstructor() {
        AnsNotFoundException exception = new AnsNotFoundException("Agent", "agent-xyz");

        assertThat(exception.getMessage()).isEqualTo("Agent not found: agent-xyz");
        assertThat(exception.getResourceType()).isEqualTo("Agent");
        assertThat(exception.getResourceId()).isEqualTo("agent-xyz");
    }

    @Test
    @DisplayName("AnsNotFoundException three-arg constructor")
    void notFoundExceptionThreeArgConstructor() {
        AnsNotFoundException exception = new AnsNotFoundException(
            "Custom message", "Resource", "res-123");

        assertThat(exception.getMessage()).isEqualTo("Custom message");
        assertThat(exception.getResourceType()).isEqualTo("Resource");
        assertThat(exception.getResourceId()).isEqualTo("res-123");
        assertThat(exception.getRequestId()).isNull();
    }

    @Test
    @DisplayName("AnsNotFoundException getAgentId returns ID for Agent type")
    void notFoundExceptionGetAgentIdForAgentType() {
        AnsNotFoundException exception = new AnsNotFoundException("Agent", "agent-456");

        assertThat(exception.getAgentId()).isEqualTo("agent-456");
    }

    @Test
    @DisplayName("AnsNotFoundException getAgentId returns null for non-Agent type")
    void notFoundExceptionGetAgentIdForNonAgentType() {
        AnsNotFoundException exception = new AnsNotFoundException("Service", "svc-789");

        assertThat(exception.getAgentId()).isNull();
    }

    @Test
    @DisplayName("AnsServerException single-arg constructor defaults to 500")
    void serverExceptionSingleArgConstructor() {
        AnsServerException exception = new AnsServerException("Server error");

        assertThat(exception.getMessage()).isEqualTo("Server error");
        assertThat(exception.getStatusCode()).isEqualTo(500);
    }

    @Test
    @DisplayName("AnsServerException two-arg constructor")
    void serverExceptionTwoArgConstructor() {
        AnsServerException exception = new AnsServerException("Bad gateway", 502);

        assertThat(exception.getMessage()).isEqualTo("Bad gateway");
        assertThat(exception.getStatusCode()).isEqualTo(502);
        assertThat(exception.getRequestId()).isNull();
    }

    @Test
    @DisplayName("AnsServerException getCode alias method")
    void serverExceptionGetCodeAlias() {
        AnsServerException exception = new AnsServerException("Error", 503);

        assertThat(exception.getCode()).isEqualTo(503);
        assertThat(exception.getCode()).isEqualTo(exception.getStatusCode());
    }

    @Test
    @DisplayName("AnsServerException isRetryable returns true for 5xx status")
    void serverExceptionIsRetryableFor5xx() {
        assertThat(new AnsServerException("Error", 500).isRetryable()).isTrue();
        assertThat(new AnsServerException("Error", 502).isRetryable()).isTrue();
        assertThat(new AnsServerException("Error", 503).isRetryable()).isTrue();
        assertThat(new AnsServerException("Error", 599).isRetryable()).isTrue();
    }

    @Test
    @DisplayName("AnsServerException isRetryable returns false for non-5xx status")
    void serverExceptionIsRetryableForNon5xx() {
        assertThat(new AnsServerException("Error", 400).isRetryable()).isFalse();
        assertThat(new AnsServerException("Error", 404).isRetryable()).isFalse();
        assertThat(new AnsServerException("Error", 499).isRetryable()).isFalse();
        assertThat(new AnsServerException("Error", 600).isRetryable()).isFalse();
    }

    @Test
    @DisplayName("AnsAuthenticationException with message and cause")
    void authExceptionMessageAndCauseConstructor() {
        RuntimeException cause = new RuntimeException("Token expired");
        AnsAuthenticationException exception = new AnsAuthenticationException(
            "Authentication failed", cause);

        assertThat(exception.getMessage()).isEqualTo("Authentication failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getRequestId()).isNull();
    }
}