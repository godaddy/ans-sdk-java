package com.godaddy.ans.sdk.transparency.scitt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ScittFetchExceptionTest {

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create exception with message and artifact type")
        void shouldCreateExceptionWithMessageAndArtifactType() {
            ScittFetchException exception = new ScittFetchException(
                "Failed to fetch", ScittFetchException.ArtifactType.RECEIPT, "test-agent");

            assertThat(exception.getMessage()).isEqualTo("Failed to fetch");
            assertThat(exception.getArtifactType()).isEqualTo(ScittFetchException.ArtifactType.RECEIPT);
            assertThat(exception.getAgentId()).isEqualTo("test-agent");
            assertThat(exception.getCause()).isNull();
        }

        @Test
        @DisplayName("Should create exception with message, cause, and artifact type")
        void shouldCreateExceptionWithCause() {
            RuntimeException cause = new RuntimeException("Network error");
            ScittFetchException exception = new ScittFetchException(
                "Failed to fetch", cause, ScittFetchException.ArtifactType.STATUS_TOKEN, "agent-123");

            assertThat(exception.getMessage()).isEqualTo("Failed to fetch");
            assertThat(exception.getCause()).isEqualTo(cause);
            assertThat(exception.getArtifactType()).isEqualTo(ScittFetchException.ArtifactType.STATUS_TOKEN);
            assertThat(exception.getAgentId()).isEqualTo("agent-123");
        }

        @Test
        @DisplayName("Should allow null agent ID for public key fetches")
        void shouldAllowNullAgentId() {
            ScittFetchException exception = new ScittFetchException(
                "Key fetch failed", ScittFetchException.ArtifactType.PUBLIC_KEY, null);

            assertThat(exception.getAgentId()).isNull();
            assertThat(exception.getArtifactType()).isEqualTo(ScittFetchException.ArtifactType.PUBLIC_KEY);
        }
    }

    @Nested
    @DisplayName("ArtifactType enum tests")
    class ArtifactTypeTests {

        @Test
        @DisplayName("Should have RECEIPT artifact type")
        void shouldHaveReceiptType() {
            assertThat(ScittFetchException.ArtifactType.RECEIPT).isNotNull();
            assertThat(ScittFetchException.ArtifactType.valueOf("RECEIPT"))
                .isEqualTo(ScittFetchException.ArtifactType.RECEIPT);
        }

        @Test
        @DisplayName("Should have STATUS_TOKEN artifact type")
        void shouldHaveStatusTokenType() {
            assertThat(ScittFetchException.ArtifactType.STATUS_TOKEN).isNotNull();
            assertThat(ScittFetchException.ArtifactType.valueOf("STATUS_TOKEN"))
                .isEqualTo(ScittFetchException.ArtifactType.STATUS_TOKEN);
        }

        @Test
        @DisplayName("Should have PUBLIC_KEY artifact type")
        void shouldHavePublicKeyType() {
            assertThat(ScittFetchException.ArtifactType.PUBLIC_KEY).isNotNull();
            assertThat(ScittFetchException.ArtifactType.valueOf("PUBLIC_KEY"))
                .isEqualTo(ScittFetchException.ArtifactType.PUBLIC_KEY);
        }

        @Test
        @DisplayName("Should have exactly 3 artifact types")
        void shouldHaveThreeArtifactTypes() {
            assertThat(ScittFetchException.ArtifactType.values()).hasSize(3);
        }
    }

    @Nested
    @DisplayName("Exception behavior tests")
    class ExceptionBehaviorTests {

        @Test
        @DisplayName("Should be throwable as RuntimeException")
        void shouldBeThrowableAsRuntimeException() {
            ScittFetchException exception = new ScittFetchException(
                "Test", ScittFetchException.ArtifactType.RECEIPT, "agent");

            assertThat(exception).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("Should preserve stack trace")
        void shouldPreserveStackTrace() {
            RuntimeException cause = new RuntimeException("Original");
            ScittFetchException exception = new ScittFetchException(
                "Wrapped", cause, ScittFetchException.ArtifactType.RECEIPT, "agent");

            assertThat(exception.getStackTrace()).isNotEmpty();
            assertThat(exception.getCause().getMessage()).isEqualTo("Original");
        }
    }
}